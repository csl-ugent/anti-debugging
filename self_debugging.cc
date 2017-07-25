/* This research is supported by the European Union Seventh Framework Programme (FP7/2007-2013), project ASPIRE (Advanced  Software Protection: Integration, Research, and Exploitation), under grant agreement no. 609734; on-line at https://aspire-fp7.eu/. */

#include "self_debugging.h"

#define SELFDEBUGGING_PREFIX "Debugger_"
#define SD_IDENTIFIER_PREFIX LINKIN_IDENTIFIER_PREFIX SELFDEBUGGING_PREFIX
#define PREFIX_FOR_LINKED_IN_SD_OBJECT "LINKED_IN_SD_OBJECT_"
#define FINAL_PREFIX_FOR_LINKED_IN_SD_OBJECT PREFIX_FOR_LINKED_IN_SD_OBJECT SD_IDENTIFIER_PREFIX
#define EF_SELF_DEBUGGING_HELL_EDGE (1<<21) /* Flag to signify this edge was created as a result of self-debugging tranformations */
#define REGS_STRUCT_OFFSET 3 /* The offset of the pt_regs struct in the t_sd_state struct, expressed in address size */
#define FL_B FL_SPSR/* Cheat by using the FL_SPSR flag to store whether a we only load/store a byte */

using namespace std;

SelfDebuggingTransformer::SelfDebuggingTransformer (t_object* obj, t_const_string output_name)
: AbstractTransformer(obj, output_name, ".diablo.anti_debugging.log", FALSE, NULL, "SELF_DEBUGGING_RELOC_LABEL", EF_SELF_DEBUGGING_HELL_EDGE)
{
  /* Link in the debugger if this is still needed */
  if(self_debugging_options.debugger)
    LinkObjectFileNew (obj, self_debugging_options.debugger, PREFIX_FOR_LINKED_IN_SD_OBJECT, FALSE, TRUE, NULL);

  /* Find the symbols in the object */
  init_sym = SymbolTableGetSymbolByName(OBJECT_SUB_SYMBOL_TABLE(obj), SD_IDENTIFIER_PREFIX"Init");
  ldr_sym = SymbolTableGetSymbolByName(OBJECT_SUB_SYMBOL_TABLE(obj), SD_IDENTIFIER_PREFIX"Ldr");
  str_sym = SymbolTableGetSymbolByName(OBJECT_SUB_SYMBOL_TABLE(obj), SD_IDENTIFIER_PREFIX"Str");
  ldm_sym = SymbolTableGetSymbolByName(OBJECT_SUB_SYMBOL_TABLE(obj), SD_IDENTIFIER_PREFIX"Ldm");
  stm_sym = SymbolTableGetSymbolByName(OBJECT_SUB_SYMBOL_TABLE(obj), SD_IDENTIFIER_PREFIX"Stm");
  nr_of_entries_sym = SymbolTableGetSymbolByName (OBJECT_SUB_SYMBOL_TABLE(obj), SD_IDENTIFIER_PREFIX "nr_of_entries");
  map_sym = SymbolTableGetSymbolByName (OBJECT_SUB_SYMBOL_TABLE(obj), SD_IDENTIFIER_PREFIX "addr_mapping");
  global_state_sym = SymbolTableGetSymbolByName (OBJECT_SUB_SYMBOL_TABLE(obj), SD_IDENTIFIER_PREFIX "global_state");

  /* Check if all symbols were found */
  ASSERT(init_sym && ldr_sym && str_sym && ldm_sym && stm_sym && map_sym && nr_of_entries_sym && global_state_sym, ("Didn't find all symbols present in the debugger object! Are you sure this object was linked in?"));

  /* The size of a map entry has been set as the first element of the map */
  map_entry_size = SectionGetData32 (T_SECTION(SYMBOL_BASE(map_sym)), SYMBOL_OFFSET_FROM_START(map_sym));
  map_sec = T_SECTION(SYMBOL_BASE(map_sym));

  /* Adapt the program so before start the initialization routine is executed */
  if (SymbolTableGetSymbolByName(OBJECT_SUB_SYMBOL_TABLE(obj), FINAL_PREFIX_FOR_LINKED_IN_SD_OBJECT "Init"))
    DiabloBrokerCall ("AddInitializationRoutine", obj, init_sym);

  LOG(L_TRANSFORMS, "START OF ANTI-DEBUGGING LOG\n");
}

SelfDebuggingTransformer::~SelfDebuggingTransformer ()
{
  LOG(L_TRANSFORMS, "END OF ANTI-DEBUGGING LOG\n");
}

/* Checks whether the region for the info provided can be transformed */
t_bool SelfDebuggingTransformer::CanTransformFunction (t_function* fun) const
{
  t_const_string log_msg = "Can't move function %s to debugger context: %s.\n";
  t_const_string fun_name = FUNCTION_NAME(fun);

  /* Small inner lambda function to do all logging and return FALSE */
  auto log_and_return_false = [=](t_const_string reason){
    VERBOSE(0, (log_msg, fun_name, reason));
    LOG(L_TRANSFORMS, log_msg, fun_name, reason);
    return FALSE;
  };

  if (FUNCTION_IS_HELL(fun))
    return log_and_return_false("it's a hell function");

  if (FUNCTION_NAME(fun))
  {
    t_const_string reason = "this function plays a part in accessing the transformed code and thus can't be transformed itself";
    t_bbl* exit_bbl = FunctionGetExitBlock(fun);
    t_bbl* entry_bbl = FUNCTION_BBL_FIRST(fun);
    t_cfg_edge* edge;

    /* Don't transform involved in accessing transformed code */
    if (StringPatternMatch("*" SD_IDENTIFIER_PREFIX "*", FUNCTION_NAME(fun)))
      return log_and_return_false(reason);

    /* If we factored out any part of this code for accessing transformed code, make sure it isn't transformed either */
    if (StringPatternMatch("factor-*", FUNCTION_NAME(fun)))
    {
      /* We take a look at the incoming edges to ascertain the function isn't called from code that shouldn't be transformed */
      BBL_FOREACH_PRED_EDGE(entry_bbl, edge)
      {
        t_bbl* head = T_BBL(CFG_EDGE_HEAD(edge));
        t_function* caller = BBL_FUNCTION(head);

        if (FUNCTION_NAME(caller) && StringPatternMatch("*" SD_IDENTIFIER_PREFIX "*", FUNCTION_NAME(caller)))
          return log_and_return_false(reason);
      }
    }

    t_regset regs_used_in_fun = RegsetNew();
    t_regset regs_defined_in_fun = RegsetNew();

    t_bbl* bbl;
    FUNCTION_FOREACH_BBL(fun, bbl)
    {
      t_ins* ins;
      BBL_FOREACH_INS(bbl, ins)
      {
        t_arm_ins* arm_ins = T_ARM_INS(ins);

        /* Don't transform any functions that contain VPUSH or VPOP */
        switch(ARM_INS_OPCODE(arm_ins))
        {
          case ARM_VPOP:
          case ARM_VPUSH:
            return log_and_return_false("the function contains VPUSH or VPOP instructions");

          case ARM_LDREX:
          case ARM_LDREXD:
          case ARM_LDREXB:
          case ARM_LDREXH:
          case ARM_STREX:
          case ARM_STREXD:
          case ARM_STREXB:
          case ARM_STREXH:
          case ARM_STRH:
          case ARM_LDRH:
          case ARM_LDRSH:
          case ARM_LDRSB:
          case ARM_LDRD:
          case ARM_STRD:
            return log_and_return_false("unsupported load/store variants present");

          case ARM_STM:
            if ((ARM_INS_REGB(arm_ins) == ARM_REG_R13) && (ARM_INS_IMMEDIATE(arm_ins) & (1 << ARM_REG_R13)))
              return log_and_return_false("not supporting STM of SP, to SP");
            if (ARM_INS_IMMEDIATE(arm_ins) & (1 << ARM_REG_R15))
              return log_and_return_false("not supporting STM of PC");

          default:
            break;
        }
      }

      BBL_FOREACH_SUCC_EDGE(bbl, edge)
      {
        if (CfgEdgeTestCategoryOr(edge, ET_CALL))
          return log_and_return_false("the function makes calls, this is not as of yet supported");

        if (CfgEdgeTestCategoryOr(edge, ET_IPSWITCH))
          return log_and_return_false("the function exits through a switch, this is not as of yet supported");

        if (CFG_EDGE_FLAGS(edge) & transformed_hell_edge_flag)
          return log_and_return_false("the function invokes an already transformed region");
      }

      RegsetSetUnion(regs_used_in_fun,BBL_REGS_USE(bbl));
      RegsetSetUnion(regs_defined_in_fun,BBL_REGS_DEF(bbl));
    }

    t_regset before_help = RegsetIntersect(FUNCTION_REGS_USED(fun), BblRegsLiveBefore(entry_bbl));
    t_regset after_help = FunctionGetExitBlock(fun) ? RegsetIntersect(FUNCTION_REGS_CHANGED(fun), BblRegsLiveAfter(FunctionGetExitBlock(fun))) : FUNCTION_REGS_CHANGED(fun);
    t_regset live_before = RegsetIntersect(before_help, regs_used_in_fun);
    t_regset live_after = RegsetIntersect(after_help, regs_defined_in_fun);

    if (!RegsetIsEmpty(RegsetIntersect(live_before, CFG_DESCRIPTION(cfg)->cond_registers)))
      return log_and_return_false("a conditional register is live on function entry, this is not as of yet supported");

    if (!RegsetIsEmpty(RegsetIntersect(live_after, CFG_DESCRIPTION(cfg)->cond_registers)))
      return log_and_return_false("a conditional register is live on function exit, this is not as of yet supported");

    BBL_FOREACH_PRED_EDGE(entry_bbl, edge)
      if (CFG_EDGE_FLAGS(edge) & transformed_hell_edge_flag)
        return log_and_return_false("the function is invoked by an already transformed region");
  }

  return TRUE;
}

void SelfDebuggingTransformer::TransformBbl (t_bbl* bbl)
{
  t_ins* ins;
  t_ins* ins_safe;
  /* Iterate in reverse over the instructions as we will use BblSplitBlock and this splits a BBL in such
   * a way that the first instructions remain in it, while the last ones are placed in a newly split off
   * BBL. If we were to iterate in forward order we would always have to adjust the bbl over which we were
   * iterating.
   */
  BBL_FOREACH_INS_R_SAFE(bbl, ins, ins_safe)
  {
    /* Don't transform any instruction that was inserted during this phase */
    if (INS_PHASE(ins) == GetDiabloPhase())
      continue;

    t_arm_ins* arm_ins = T_ARM_INS(ins);
    switch (ARM_INS_OPCODE(arm_ins))
    {
      /* If we're only loading/storing a byte, temporarily set a flag indicating this */
      case ARM_STRB:
        ARM_INS_SET_FLAGS(arm_ins, ARM_INS_FLAGS(arm_ins) | FL_B);
      case ARM_STR:
        TransformStr(bbl, arm_ins);
        break;
      case ARM_LDRB:
        ARM_INS_SET_FLAGS(arm_ins, ARM_INS_FLAGS(arm_ins) | FL_B);
      case ARM_LDR:
        TransformLdr(bbl, arm_ins);
        break;
      case ARM_STM:
        TransformStm(bbl, arm_ins);
        break;
      case ARM_LDM:
        TransformLdm(bbl, arm_ins);
        break;
      default:
        TransformUseOfSP(bbl, arm_ins);
    }
  }
}

void SelfDebuggingTransformer::TransformEntrypoint(t_function* fun)
{
  /* We will split the entry BBL before its first instruction. The newly split off BBL contains all of its original instructions
   * and the original BBL (which is still the entrypoint) is now empty, and ready to be populated.
   */
  t_bbl* entry = FUNCTION_BBL_FIRST(fun);
  t_bbl* old_entry = BblSplitBlock(entry, T_INS(BBL_INS_FIRST(entry)), TRUE);

  /* Take care of intraprocedural edges that end on the entrypoint, these should keep the old entrypoint as their tail */
  t_cfg_edge* edge, *edge_s;
  BBL_FOREACH_PRED_EDGE_SAFE(entry, edge, edge_s)
    if (!CfgEdgeIsInterproc(edge))
      CfgEdgeChangeTail(edge, old_entry);

  /* We will generate the following code for the new entrypoint:
   * PUSH {FP, LR}
   * ADR state_reg, global_state (load the global state)
   * STR SP, [state_reg + 2 * adr_size] (store the stack pointer in the state struct)
   * RESTORE REGISTER CONTEXT (this comes down to loading all registers live before entry from the regs struct)
   * [OPTIONAL] LDR state_reg, [state_reg + (REGS_STRUCT_OFFSET + state_reg#) * adr_size]
   */
  t_arm_ins* arm_ins;
  t_bool isThumb = ArmBblIsThumb(old_entry);

  /* Find out how many dead registers are available, preferably we use a dead register that won't need to be restored */
  /* First, find out which registers are live upon entry */
  t_regset regs_used_in_fun = RegsetNew();
  t_bbl * bbl;
  FUNCTION_FOREACH_BBL(fun,bbl)
    RegsetSetUnion(regs_used_in_fun,BBL_REGS_USE(bbl));
  t_regset live_before = RegsetIntersect(BblRegsLiveBefore(old_entry), regs_used_in_fun);

  t_regset available = RegsetDiff(possible, live_before);
  t_uint32 nr_of_dead_regs = RegsetCountRegs(available);

  /* The default register is R0, this might get changed if there is another dead register available */
  t_reg state_reg = ARM_REG_R0;
  if (nr_of_dead_regs != 0)
    REGSET_FOREACH_REG(available, state_reg)
      break;

  ArmMakeInsForBbl(Push, Append, arm_ins, entry, isThumb, (1 << ARM_REG_R11) | (1 << ARM_REG_R14), ARM_CONDITION_AL, isThumb);

  /* Produce the address of the state struct */
  ArmMakeInsForBbl(Mov, Append, arm_ins, entry, isThumb, state_reg, ARM_REG_NONE, 0, ARM_CONDITION_AL);
  t_reloc* reloc = RelocTableAddRelocToRelocatable(
      OBJECT_RELOC_TABLE(obj),
      AddressNullForObject(obj), /* addend */
      T_RELOCATABLE(arm_ins), /* from */
      AddressNullForObject(obj),  /* from-offset */
      SYMBOL_BASE(global_state_sym), /* to */
      SYMBOL_OFFSET_FROM_START(global_state_sym), /* to-offset */
      FALSE, /* hell */
      NULL, /* edge*/
      NULL, /* corresp */
      NULL, /* sec */
      "R00A00+" "\\" WRITE_32);
  ArmInsMakeAddressProducer(arm_ins, 0 /* immediate */, reloc);

  /* Put the debugger's stack pointer in the state struct, before we overwrite it */
  ArmMakeInsForBbl(Str, Append, arm_ins, entry, isThumb, ARM_REG_R13, state_reg, ARM_REG_NONE, 2 * adr_size, ARM_CONDITION_AL, TRUE, TRUE, FALSE);

  /* Append the instructions needed to restore the register context */
  DEBUG(("live before: @X",CPREGSET(FUNCTION_CFG(fun),live_before)));
  AppendInstructionsToRestoreRegisterContext(entry, live_before, state_reg);

  /* If there were no dead registers available and we had to use R0, load its actual value from the regs struct now */
  if(nr_of_dead_regs == 0)
    ArmMakeInsForBbl(Ldr, Append, arm_ins, entry, isThumb, state_reg, state_reg, ARM_REG_NONE, (REGS_STRUCT_OFFSET + state_reg) * adr_size, ARM_CONDITION_AL, TRUE, TRUE, FALSE);
}

void SelfDebuggingTransformer::TransformExit (t_cfg_edge* edge)
{
  /* Now we can transform this edge as if it was a normal outgoing edge */
  t_bbl* bbl = T_BBL(CFG_EDGE_HEAD(edge));
  TransformOutgoingEdgeImpl (bbl, edge, NULL);
}

void SelfDebuggingTransformer::TransformIncomingEdgeImpl (t_bbl* bbl, t_cfg_edge* edge)
{
  /* We will append the following code:
   * [OPTIONAL] PUSH {R0, R1} (if there are no dead regs)
   * CONST const_reg, $constant
   * There are two options in which to get the constant on stack:
   * 1.: PUSH const_reg
   * 2.: STR const_reg [SP + 4] (no dead regs, R0 is const_reg)
   *     POP const_reg
   * [OPTIONAL] ADR LR, return_bbl (if we're dealing with a call edge)
   * BKPT 0x0000
   */
  t_arm_ins* arm_ins;

  /* Find out how many registers there are available */
  t_regset available = RegsetDiff(possible, BblRegsLiveAfter(bbl));
  t_uint32 nr_of_dead_regs = RegsetCountRegs(available);

  /* Find a dead register to produce the constant in. If we don't find one, push and pop a live reg */
  t_bool isThumb = ArmBblIsThumb(bbl);
  t_reg const_reg;
  if (nr_of_dead_regs == 0)
  {
    const_reg = ARM_REG_R0;
    ArmMakeInsForBbl(Push, Append, arm_ins, bbl, isThumb, (1 << const_reg) | (1 << ARM_REG_R1), ARM_CONDITION_AL, isThumb);
  }
  else
    REGSET_FOREACH_REG(available, const_reg)
      break;

  /* Create the constant */
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, const_reg, ARM_REG_NONE, 0, ARM_CONDITION_AL);
  ArmMakeConstantProducer(arm_ins, constant);

  /* We will place the constant on the top of the stack. The exact way in which we do this depends on whether
   * we can use a dead register or not. If we do we simply push the register containing the constant. If we
   * don't we still have to pop the saved contents of the live register we used to create the constant, and
   * thus we have to be a little creative. We will store the constant in the slot beneath the stack pointer
   * (of which we are certain it contains nothing), and then pop the first stack slot into the used register.
   */
  if (nr_of_dead_regs == 0)
  {
    ArmMakeInsForBbl(Str, Append, arm_ins, bbl, isThumb, const_reg, ARM_REG_R13, ARM_REG_NONE, adr_size, ARM_CONDITION_AL, TRUE, TRUE, FALSE);
    ArmMakeInsForBbl(Pop, Append, arm_ins, bbl, isThumb, 1 << const_reg, ARM_CONDITION_AL, isThumb);
  }
  else
    ArmMakeInsForBbl(Push, Append, arm_ins, bbl, isThumb, (1 << const_reg), ARM_CONDITION_AL, isThumb);

  /* If we're dealing with a call edge, emulate the call by moving the return address to LR */
  if (CfgEdgeTestCategoryOr(edge, ET_CALL))
  {
    ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R14, ARM_REG_NONE, 0, ARM_CONDITION_AL);
    t_bbl* bbl_successor = CFG_EDGE_TAIL(CFG_EDGE_CORR(edge));
    t_reloc* reloc = RelocTableAddRelocToRelocatable(
       OBJECT_RELOC_TABLE(obj),
       AddressNullForObject(obj), /* addend */
       T_RELOCATABLE(arm_ins), /* from */
       AddressNullForObject(obj),  /* from-offset */
       T_RELOCATABLE(bbl_successor), /* to */
       AddressNullForObject(obj), /* to-offset */
       FALSE, /* hell */
       NULL, /* edge*/
       NULL, /* corresp */
       NULL, /* sec */
       "R00A00+" "\\" WRITE_32);
    ArmInsMakeAddressProducer(arm_ins, 0 /* immediate */, reloc);
  }

  /* Create the breakpoint to switch to the debugger */
  ArmMakeInsForBbl(Bkpt, Append, arm_ins, bbl, isThumb);

  t_regset regs_use = ARM_INS_REGS_USE(arm_ins);
  RegsetSetSubReg(regs_use, ARM_REG_CPSR);
  ARM_INS_SET_REGS_USE(arm_ins,regs_use);

  /* Adjust the incoming edge to go to hell */
  CfgEdgeChangeTail(edge, CFG_HELL_NODE(cfg));
  CFG_EDGE_SET_CAT(edge, ET_IPJUMP);
  CFG_EDGE_SET_FLAGS(edge, CFG_EDGE_FLAGS(edge) | transformed_hell_edge_flag);
}

void SelfDebuggingTransformer::TransformIncomingTransformedEdgeImpl (t_arm_ins* ins, t_reloc* reloc)
{
  /* TODO: Implement! */
}

void SelfDebuggingTransformer::TransformOutgoingEdgeImpl (t_bbl* bbl, t_cfg_edge* edge, t_relocatable* to)
{
  /* We will append the following code:
   * [OPTIONAL] PUSH state_reg (in case there are no dead registers available, push ARM_REG_R0)
   * ADR state_reg, global_state (load the t_sd_state struct)
   * BACKUP REGISTER CONTEXT (this comes down to storing all registers live after exit to the regs struct)
   * [OPTIONAL] ADR helper1, DESTINATION (this register will contain the destination address or some other controlflow-related value)
   * [OPTIONAL] STR helper1, [state_reg] (put the destination address into the t_sd_state struct)
   * [OPTIONAL] ADR helper2, LINK (this register will contain the link address in case the outgoing edge is a ET_CALL)
   * [OPTIONAL] STR helper2, [state_reg + adr_size] (put the link address into the t_sd_state struct)
   * [OPTIONAL] POP helper1 (in case there are no dead registers, we also need to store the pushed value of state_reg in the pt_regs struct)
   * [OPTIONAL] STR helper1, [state_reg + (REGS_STRUCT_OFFSET + state_reg) * adr_size]
   * LDR SP, [state_reg + 2 * adr_size] (reload the original stack pointer)
   * POP {FP, PC}
   */
  t_bool isThumb = ArmBblIsThumb(bbl);
  t_arm_ins* arm_ins, *dest_ins, *link_ins;
  t_arm_ins* ret_ins = T_ARM_INS(BBL_INS_LAST(bbl));

  /* Append the instructions needed to backup the register context */
  t_regset regs_defined_in_fun = RegsetNew();
  t_bbl * bbl2;
  FUNCTION_FOREACH_BBL(BBL_FUNCTION(bbl),bbl2)
    RegsetSetUnion(regs_defined_in_fun,BBL_REGS_DEF(bbl2));
  t_regset live_after = RegsetIntersect(BblRegsLiveAfter(bbl), regs_defined_in_fun);
  t_regset available = RegsetDiff(possible, live_after);
  t_uint32 nr_of_dead_regs = RegsetCountRegs(available);

  /* Find a dead register to produce the constant in. If we don't find one, push and pop a live reg */
  t_reg state_reg;
  if (nr_of_dead_regs == 0)
  {
    state_reg = ARM_REG_R0;
    ArmMakeInsForBbl(Push, Append, arm_ins, bbl, isThumb, (1 << state_reg), ARM_CONDITION_AL, isThumb);
  }
  else
    REGSET_FOREACH_REG(available, state_reg)
      break;

  /* Produce the address of the t_sd_state struct */
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, state_reg, ARM_REG_NONE, 0, ARM_CONDITION_AL);
  t_reloc* reloc = RelocTableAddRelocToRelocatable(
      OBJECT_RELOC_TABLE(obj),
      AddressNullForObject(obj), /* addend */
      T_RELOCATABLE(arm_ins), /* from */
      AddressNullForObject(obj),  /* from-offset */
      SYMBOL_BASE(global_state_sym), /* to */
      SYMBOL_OFFSET_FROM_START(global_state_sym), /* to-offset */
      FALSE, /* hell */
      NULL, /* edge*/
      NULL, /* corresp */
      NULL, /* sec */
      "R00A00+" "\\" WRITE_32);
  ArmInsMakeAddressProducer(arm_ins, 0 /* immediate */, reloc);
  DEBUG(("live after: @X",CPREGSET(BBL_CFG(bbl),live_after)));
  AppendInstructionsToBackupRegisterContext(bbl, live_after, state_reg);

  /* Choose the two helper registers so they don't conflict with the state_reg */
  t_reg helper1 = (state_reg == ARM_REG_R0) ? ARM_REG_R1 : ARM_REG_R0;
  t_reg helper2 = (state_reg == ARM_REG_R2) ? ARM_REG_R3 : ARM_REG_R2;

  t_cfg* target_cfg = BBL_CFG(CFG_EDGE_TAIL(edge));
  switch(CFG_EDGE_CAT(edge))
  {
    case ET_CALL:
    {
      ArmMakeInsForBbl(Mov, Append, link_ins, bbl, isThumb, helper2, ARM_REG_NONE, 0, ARM_CONDITION_AL);

      /* Get the address that should go into the link register, then fall through */
      t_bbl* bbl_successor = CFG_EDGE_TAIL(CFG_EDGE_CORR(edge));
      t_reloc* reloc = RelocTableAddRelocToRelocatable(
         OBJECT_RELOC_TABLE(obj),
         AddressNullForObject(obj), /* addend */
         T_RELOCATABLE(link_ins), /* from */
         AddressNullForObject(obj),  /* from-offset */
         T_RELOCATABLE(bbl_successor), /* to */
         AddressNullForObject(obj), /* to-offset */
         FALSE, /* hell */
         NULL, /* edge*/
         NULL, /* corresp */
         NULL, /* sec */
         "R00A00+" "\\" WRITE_32);
      ArmInsMakeAddressProducer(link_ins, 0 /* immediate */, reloc);

      ArmMakeInsForBbl(Str, Append, arm_ins, bbl, isThumb, helper2, state_reg, ARM_REG_NONE, adr_size, ARM_CONDITION_AL, TRUE, TRUE, FALSE);
    }

    case ET_IPFALLTHRU:
    case ET_IPJUMP:
    {
      ArmMakeInsForBbl(Mov, Append, dest_ins, bbl, isThumb, helper1, ARM_REG_NONE, 0, ARM_CONDITION_AL);

      /* Get the address that should we should continue executing on, back in the debuggee's context */
      t_reloc* reloc = RelocTableAddRelocToRelocatable(
         OBJECT_RELOC_TABLE(obj),
         AddressNullForObject(obj), /* addend */
         T_RELOCATABLE(dest_ins), /* from */
         AddressNullForObject(obj),  /* from-offset */
         T_RELOCATABLE(to), /* to */
         AddressNullForObject(obj), /* to-offset */
         FALSE, /* hell */
         NULL, /* edge*/
         NULL, /* corresp */
         NULL, /* sec */
         "R00A00+" "\\" WRITE_32);
      ArmInsMakeAddressProducer(dest_ins, 0 /* immediate */, reloc);

      ArmMakeInsForBbl(Str, Append, arm_ins, bbl, isThumb, helper1, state_reg, ARM_REG_NONE, 0, ARM_CONDITION_AL, TRUE, TRUE, FALSE);
      break;
    }

    case ET_JUMP:
    {
      if (ARM_INS_REGA(ret_ins) == ARM_REG_R15)
      {
        /* If the last instruction sets the PC, it's still the original return instruction and should be replaced */
        InsKill (T_INS(ret_ins));
        ArmMakeInsForBbl(Mov, Append, dest_ins, bbl, isThumb, helper1, ARM_REG_NONE, 1, ARM_CONDITION_AL);
        ArmMakeInsForBbl(Str, Append, arm_ins, bbl, isThumb, helper1, state_reg, ARM_REG_NONE, 0, ARM_CONDITION_AL, TRUE, TRUE, FALSE);
      }
      break;
    }

    case ET_IPSWITCH:
    {
      FATAL(("Unsupported for now!"));
    }

    default:
    {
      FATAL(("Case not implemented!"));
    }
  }

  /* Common stuff for the interprocedural edges. We will return back to the debuggee context, so make this edge a jump to the return block.
   * We should also create a new HELL edge incoming to the old target of this edge.
   */
  if (CFG_EDGE_CAT(edge) != ET_JUMP)
  {
    CFG_EDGE_SET_CAT(edge, ET_JUMP);
    t_cfg_edge* ip = CfgEdgeCreate (target_cfg, CFG_HELL_NODE(target_cfg), T_BBL(CFG_EDGE_TAIL(edge)), ET_IPJUMP);
    CFG_EDGE_SET_FLAGS(ip, CFG_EDGE_FLAGS(ip) | transformed_hell_edge_flag);
    CfgEdgeCreateCompensating (target_cfg, ip);
    CfgEdgeChangeTail(edge, FunctionGetExitBlock(BBL_FUNCTION(bbl)));/* TODO: What if there's no exit block? */
  }

  if (nr_of_dead_regs == 0)
  {
    /* Pop the previously pushed value of the state_reg into the first helper and store it in the pt_regs struct */
    ArmMakeInsForBbl(Pop, Append, arm_ins, bbl, isThumb, (1 << helper1), ARM_CONDITION_AL, isThumb);
    ArmMakeInsForBbl(Str, Append, arm_ins, bbl, isThumb, helper1, state_reg, ARM_REG_NONE, (REGS_STRUCT_OFFSET + state_reg) * adr_size, ARM_CONDITION_AL, TRUE, TRUE, FALSE);
  }

  /* Restore the debugger's stack pointer */
  ArmMakeInsForBbl(Ldr, Append, arm_ins, bbl, isThumb, ARM_REG_R13, state_reg, ARM_REG_NONE, 2 * adr_size, ARM_CONDITION_AL, TRUE, TRUE, FALSE);

  /* Insert instruction to exit back to the debugger that called this fragment */
  ArmMakeInsForBbl(Pop, Append, arm_ins, bbl, isThumb, (1 << ARM_REG_R11) | (1 << ARM_REG_R15), ARM_CONDITION_AL, isThumb);
}

void SelfDebuggingTransformer::AppendInstructionsToRestoreRegisterContext(t_bbl* bbl, t_regset regset, t_reg state_reg)
{
  /* We will append the following code:
   * LDR R#, [state_reg + (REGS_STRUCT_OFFSET + R#) * adr_size] (for every register that was live before!)
   */
  t_bool isThumb = ArmBblIsThumb(bbl);
  t_arm_ins* arm_ins;

  /* Don't restore SP or PC */
  RegsetSetSubReg(regset, ARM_REG_R13);
  RegsetSetSubReg(regset, ARM_REG_R15);

  t_reg reg;
  REGSET_FOREACH_REG(regset, reg)
  {
    if(reg != state_reg)
    {
      switch(ArmRegisterGetType(reg))
      {
        case REG_TYPE_INT:
          ArmMakeInsForBbl(Ldr, Append, arm_ins, bbl, isThumb, reg, state_reg, ARM_REG_NONE, (REGS_STRUCT_OFFSET + reg) * adr_size, ARM_CONDITION_AL, TRUE, TRUE, FALSE);
          break;
        case REG_TYPE_FP:
          //TODO: Figure out what to do with this!
          //ArmMakeInsForBbl(Vldr, Append, arm_ins, bbl, isThumb, reg, state_reg, ARM_REG_NONE, (REGS_STRUCT_OFFSET + reg) * adr_size, ARM_CONDITION_AL, TRUE, TRUE);
          break;
        case REG_TYPE_FLAG:
          VERBOSE(0, ("%s error not implemented yet",ArmRegisterName(reg)));
      }
    }
  }
}

void SelfDebuggingTransformer::AppendInstructionsToBackupRegisterContext(t_bbl* bbl, t_regset regset, t_reg state_reg)
{
  /* We will append the following code: (state_reg already contains the address of the t_sd_state struct)
   * STR R#, [state_reg + (REGS_STRUCT_OFFSET + R#) * adr_size] (for every register that is live after!)
   */
  t_bool isThumb = ArmBblIsThumb(bbl);
  t_arm_ins* arm_ins;

  /* Don't backup SP or PC */
  RegsetSetSubReg(regset, ARM_REG_R13);
  RegsetSetSubReg(regset, ARM_REG_R15);

  t_reg reg;
  REGSET_FOREACH_REG(regset, reg)
  {
    if(reg != state_reg)
    {
      switch(ArmRegisterGetType(reg))
      {
        case REG_TYPE_INT:
          ArmMakeInsForBbl(Str, Append, arm_ins, bbl, isThumb, reg, state_reg, ARM_REG_NONE, (REGS_STRUCT_OFFSET + reg) * adr_size, ARM_CONDITION_AL, TRUE, TRUE, FALSE);
          break;
        case REG_TYPE_FP:
          //TODO: Figure out what to do with this!
          //ArmMakeInsForBbl(Vstr, Append, arm_ins, bbl, isThumb, reg, state_reg, ARM_REG_NONE, (REGS_STRUCT_OFFSET + reg) * adr_size, ARM_CONDITION_AL, TRUE, TRUE);
          break;
        case REG_TYPE_FLAG:
          VERBOSE(0, ("%s error not implemented yet",ArmRegisterName(reg)));
      }
    }
  }
}

void SelfDebuggingTransformer::TransformLdr (t_bbl* bbl, t_arm_ins* orig_ins)
{
  /* Get some information about the instruction to replace and split its BBL in front of it */
  t_bool isThumb = ArmBblIsThumb(bbl);
  t_reg target = ARM_INS_REGA(orig_ins);
  t_reg base = ARM_INS_REGB(orig_ins);
  t_reg immediate = ARM_INS_REGC(orig_ins);
  t_arm_condition_code condition = ARM_INS_CONDITION(orig_ins);
  t_bbl* bbl_split = BblSplitBlock(bbl, T_INS(orig_ins), TRUE);

  /* In case the instruction is conditional, we need to do some more splitting */
  t_arm_ins* arm_ins;
  if (condition != ARM_CONDITION_AL)
  {
    /* Append a conditional jump to bbl. This will fall through onto the split off BBL, and jump to
     * another BBL created in between these two BBLs that contains the conditional instructions.
     */
    ArmMakeInsForBbl(CondBranch, Append, arm_ins, bbl, isThumb, condition);

    /* This BBL will contain the conditional instructions */
    t_bbl* tmp = BblSplitBlock(bbl, T_INS(arm_ins), FALSE);
    CFG_EDGE_SET_CAT(BBL_SUCC_FIRST(bbl), ET_JUMP);/* Make the fallthrough edge created into a jump edge */

    /* tmp2 is the original bbl_split and will be our fallthrough if the condition is not satisfied. The
     * bbl_split bbl will contain more conditional instructions. */
    t_bbl* tmp2 = BblSplitBlock(bbl_split, BBL_INS_FIRST(bbl_split), TRUE);
    CFG_EDGE_SET_CAT(BBL_SUCC_FIRST(bbl_split), ET_JUMP);/* Make the fallthrough edge created into a jump edge */
    ArmMakeInsForBbl(UncondBranch, Append, arm_ins, bbl_split, isThumb);

    CfgEdgeCreate (cfg, bbl, tmp2, ET_FALLTHROUGH);

    /* We will start appending instructions to this newly created BBL */
    bbl = tmp;
  }

  /* The Ldr will be replaced by the following code:
   * PUSH ALL_LIVE_CALLER_SAVED
   * PUSH {[OPT] base, [OPT] PC} (we'll push the PC if necessary to align the stack, and push the base if it's not SP)
   * [OPTIONAL] MOV R1, immediate (this immediate might be a register or a constant, only move register if it isn't there yet)
   * MOV R0, SP OR ADR R0, global_state.regs.uregs[13] (now we have the address of the base address as first argument)
   * MOV R2, FLAGS (put the flags of the original instruction in R2 as third argument)
   * [OPTIONAL] MRS cond_reg
   * BL function_ldr
   * [OPTIONAL] MSR cond_reg
   * MOV target, R0
   * [OPTIONAL] POP {base} (in case base and target are the same register or base is R13, we won't do a pop)
   * [OPTIONAL] ADD SP, SP, #4 (if alignment requires it)
   * POP ALL_LIVE_CALLER_SAVED
   */

  /* Find all the caller-saved registers that are live and thus need to be saved and restored when inserting a call */
  t_regset regs_live = RegsetIntersect(CFG_DESCRIPTION(cfg)->callee_may_change, InsRegsLiveBefore(T_INS(orig_ins)));
  t_regset int_to_push = RegsetIntersect(CFG_DESCRIPTION(cfg)->int_registers, regs_live);
  t_regset cond_to_push = RegsetIntersect(CFG_DESCRIPTION(cfg)->cond_registers, regs_live);
  t_bool save_cond = !RegsetIsEmpty(cond_to_push);
  RegsetSetSubReg(int_to_push, ARM_REG_R15);
  RegsetSetSubReg(int_to_push, target);
  RegsetSetSubReg(int_to_push, base);
  t_reg cond_reg = ARM_REG_R4;/* A callee-saved register */
  if (save_cond)
    RegsetSetAddReg(int_to_push, cond_reg);

  /* If the stack is not aligned with this push, we will align it later on in the next push */
  t_uint32 nr_of_regs_pushed = RegsetCountRegs(int_to_push);
  t_bool aligned = ((nr_of_regs_pushed % 2) == 0);

  /* Backup all live registers */
  t_uint32 regs = RegsetToUint32(int_to_push);
  ArmMakeInsForBbl(Push, Append, arm_ins, bbl, isThumb, regs, ARM_CONDITION_AL, isThumb);

  /* The first argument is a pointer to the base address. If the base is the stack pointer we only have to align (getting the pointer into
   * r0 will taken care of later on. For any other register we put it on the stack so we can take its address. Take care of alignment.
   */
  if (base == ARM_REG_R13)
  {
    if (!aligned)
      ArmMakeInsForBbl(Push, Append, arm_ins, bbl, isThumb, (1 << ARM_REG_R15), ARM_CONDITION_AL, isThumb);
  }
  else
  {
    if (aligned)
      ArmMakeInsForBbl(Push, Append, arm_ins, bbl, isThumb, (1 << base) | (1 << ARM_REG_R15), ARM_CONDITION_AL, isThumb);
    else
      ArmMakeInsForBbl(Push, Append, arm_ins, bbl, isThumb, (1 << base), ARM_CONDITION_AL, isThumb);
  }

  /* As second argument we pass the offset (which is either encoded as an immediate or present in a register) */
  if (ARM_INS_FLAGS(orig_ins) & FL_IMMED)
  {
    ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R1, ARM_REG_NONE, 0, ARM_CONDITION_AL);
    ArmMakeConstantProducer(arm_ins, ARM_INS_IMMEDIATE(orig_ins));
  }
  else if (immediate != ARM_REG_R1)
    ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R1, immediate, 0, ARM_CONDITION_AL);

  /* We want the address of the base register in r0, so we can write to it if necessary. If the base is the stack pointer,
   * we will put the address of the stack pointer in the global_state.regs struct into r0. If not, the contents of the base
   * register have been pushed are now at the top of the stack. Moving the value of the stack pointer to r0 should suffice.
   */
  if (base == ARM_REG_R13)
  {
    /* Produce the address of the stored SP in the state struct */
    ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R0, ARM_REG_NONE, 0, ARM_CONDITION_AL);
    t_reloc* reloc = RelocTableAddRelocToRelocatable(
        OBJECT_RELOC_TABLE(obj),
        AddressNullForObject(obj), /* addend */
        T_RELOCATABLE(arm_ins), /* from */
        AddressNullForObject(obj),  /* from-offset */
        SYMBOL_BASE(global_state_sym), /* to */
        AddressAdd(SYMBOL_OFFSET_FROM_START(global_state_sym), AddressNewForObject(obj, 16 * adr_size)), /* to-offset */
        FALSE, /* hell */
        NULL, /* edge*/
        NULL, /* corresp */
        NULL, /* sec */
        "R00A00+" "\\" WRITE_32);
    ArmInsMakeAddressProducer(arm_ins, 0 /* immediate */, reloc);
  }
  else
    ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R0, ARM_REG_R13, 0, ARM_CONDITION_AL);

  /* The third argument are the flags */
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R2, ARM_REG_NONE, ARM_INS_FLAGS(orig_ins), ARM_CONDITION_AL);

  /* Backup the flags */
  if (save_cond)
    ArmMakeInsForBbl(Mrs, Append, arm_ins, bbl, isThumb, cond_reg, ARM_CONDITION_AL);

  /* Do the actual call */
  ArmMakeInsForBbl(CondBranchAndLink, Append, arm_ins, bbl, isThumb, ARM_CONDITION_AL);

  /* Restore all live registers */
  ArmMakeInsForBbl(Pop, Prepend, arm_ins, bbl_split, isThumb, regs, ARM_CONDITION_AL, isThumb);

  /* Take care of alignment if necessary */
  if (base == ARM_REG_R13)
  {
    if (!aligned)
      ArmMakeInsForBbl(Add, Prepend, arm_ins, bbl_split, isThumb, ARM_REG_R13, ARM_REG_R13, ARM_REG_NONE, adr_size, ARM_CONDITION_AL);/* Reclaim the stack space */
  }
  else if (base == target)
  {
    if (aligned)
      ArmMakeInsForBbl(Add, Prepend, arm_ins, bbl_split, isThumb, ARM_REG_R13, ARM_REG_R13, ARM_REG_NONE, 2 * adr_size, ARM_CONDITION_AL);/* Reclaim the stack space */
    else
      ArmMakeInsForBbl(Add, Prepend, arm_ins, bbl_split, isThumb, ARM_REG_R13, ARM_REG_R13, ARM_REG_NONE, adr_size, ARM_CONDITION_AL);/* Reclaim the stack space */
  }
  else if (aligned)
    ArmMakeInsForBbl(Add, Prepend, arm_ins, bbl_split, isThumb, ARM_REG_R13, ARM_REG_R13, ARM_REG_NONE, adr_size, ARM_CONDITION_AL);/* Reclaim the stack space */

  /* Pop the - potentially - changed register back (unless when it's the stack pointer or the target) */
  if ((base != ARM_REG_R13) && (base != target))
    ArmMakeInsForBbl(Pop, Prepend, arm_ins, bbl_split, isThumb, (1 << base), ARM_CONDITION_AL, isThumb);

  /* Move the result into the target register (we're prepending, so this instruction will be executed first in this BBL */
  ArmMakeInsForBbl(Mov, Prepend, arm_ins, bbl_split, isThumb, target, ARM_REG_R0, 0, ARM_CONDITION_AL);

  /* Restore the flags */
  if (save_cond)
    ArmMakeInsForBbl(Msr, Prepend, arm_ins, bbl_split, isThumb, cond_reg, ARM_CONDITION_AL, TRUE);

  /* Kill the fallthrough edge that was created by BblSplitBlock, and create the edges for the call/return to function_ldr */
  CfgEdgeKill(BBL_SUCC_FIRST(bbl));
  CfgEdgeCreateCall(cfg, bbl, FUNCTION_BBL_FIRST(function_ldr), bbl_split, FunctionGetExitBlock(function_ldr));

  /* Remove the instruction now that it has been replaced by a function call */
  InsKill(T_INS(orig_ins));
}

void SelfDebuggingTransformer::TransformStr(t_bbl* bbl, t_arm_ins* orig_ins)
{
  /* Get some information about the instruction to replace and split its BBL in front of it */
  t_bool isThumb = ArmBblIsThumb(bbl);
  t_reg value = ARM_INS_REGA(orig_ins);
  t_reg base = ARM_INS_REGB(orig_ins);
  t_reg immediate = ARM_INS_REGC(orig_ins);
  t_arm_condition_code condition = ARM_INS_CONDITION(orig_ins);
  t_bbl* bbl_split = BblSplitBlock(bbl, T_INS(orig_ins), TRUE);

  /* In case the instruction is conditional, we need to do some more splitting */
  t_arm_ins* arm_ins;
  if (condition != ARM_CONDITION_AL)
  {
    /* Append a conditional jump to bbl. This will fall through onto the split off BBL, and jump to
     * another BBL created in between these two BBLs that contains the conditional instructions.
     */
    ArmMakeInsForBbl(CondBranch, Append, arm_ins, bbl, isThumb, condition);

    /* This BBL will contain the conditional instructions */
    t_bbl* tmp = BblSplitBlock(bbl, T_INS(arm_ins), FALSE);
    CFG_EDGE_SET_CAT(BBL_SUCC_FIRST(bbl), ET_JUMP);/* Make the fallthrough edge created into a jump edge */

    /* tmp2 is the original bbl_split and will be our fallthrough if the condition is not satisfied. The
     * bbl_split bbl will contain more conditional instructions. */
    t_bbl* tmp2 = BblSplitBlock(bbl_split, BBL_INS_FIRST(bbl_split), TRUE);
    CFG_EDGE_SET_CAT(BBL_SUCC_FIRST(bbl_split), ET_JUMP);/* Make the fallthrough edge created into a jump edge */
    ArmMakeInsForBbl(UncondBranch, Append, arm_ins, bbl_split, isThumb);

    CfgEdgeCreate (cfg, bbl, tmp2, ET_FALLTHROUGH);

    /* We will start appending instructions to this newly created BBL */
    bbl = tmp;
  }

  /* The Str will be replaced by the following code:
   * PUSH ALL_LIVE_CALLER_SAVED
   * PUSH {[OPT] base, [OPT] PC} (we'll push the PC if necessary to align the stack, and push the base if it's not SP)
   * [OPTIONAL] MOV [R1 or R3], immediate (only if the immediate value is in R2 and we need to move it before putting the value in there)
   * [OPTIONAL] MOV R2, value (only move to this register if it isn't already in the register)
   * [OPTIONAL] MOV R1, immediate (this immediate might be a register or a constant, only move if its necessary)
   * MOV R0, SP OR ADR R0, global_state.regs.uregs[13] (now we have the address of the base address as first argument)
   * MOV R3, FLAGS (put the flags of the original instruction in R2 as third argument)
   * [OPTIONAL] MRS cond_reg
   * BL function_str
   * [OPTIONAL] MSR cond_reg
   * POP {base}
   * [OPTIONAL] ADD SP, SP, #4
   * POP ALL_LIVE_CALLER_SAVED
   */

  /* Find all the caller-saved registers that are live and thus need to be saved and restored when inserting a call */
  t_regset regs_live = RegsetIntersect(CFG_DESCRIPTION(cfg)->callee_may_change, InsRegsLiveBefore(T_INS(orig_ins)));
  t_regset int_to_push = RegsetIntersect(CFG_DESCRIPTION(cfg)->int_registers, regs_live);
  t_regset cond_to_push = RegsetIntersect(CFG_DESCRIPTION(cfg)->cond_registers, regs_live);
  t_bool save_cond = !RegsetIsEmpty(cond_to_push);
  RegsetSetSubReg(int_to_push, ARM_REG_R15);
  RegsetSetSubReg(int_to_push, base);
  t_reg cond_reg = ARM_REG_R4;/* A callee-saved register */
  if (save_cond)
    RegsetSetAddReg(int_to_push, cond_reg);

  /* If the stack is not aligned with this push, we will align it later on in the next push */
  t_uint32 nr_of_regs_pushed = RegsetCountRegs(int_to_push);
  t_bool aligned = ((nr_of_regs_pushed % 2) == 0);

  /* Backup all live registers */
  t_uint32 regs = RegsetToUint32(int_to_push);
  ArmMakeInsForBbl(Push, Append, arm_ins, bbl, isThumb, regs, ARM_CONDITION_AL, isThumb);

  /* The first argument is a pointer to the base address. If the base is the stack pointer we only have to align (getting the pointer into
   * r0 will taken care of later on. For any other register we put it on the stack so we can take its address. Take care of alignment.
   */
  if (base == ARM_REG_R13)
  {
    if (!aligned)
      ArmMakeInsForBbl(Push, Append, arm_ins, bbl, isThumb, (1 << ARM_REG_R15), ARM_CONDITION_AL, isThumb);
  }
  else
  {
    if (aligned)
      ArmMakeInsForBbl(Push, Append, arm_ins, bbl, isThumb, (1 << base) | (1 << ARM_REG_R15), ARM_CONDITION_AL, isThumb);
    else
      ArmMakeInsForBbl(Push, Append, arm_ins, bbl, isThumb, (1 << base), ARM_CONDITION_AL, isThumb);
  }

  /* The third argument is the value to be stored */
  if (value != ARM_REG_R2)
  {
    /* If the value isn't already in the right register, it might be occupied by the immediate.
     * Make sure we don't accidentally overwrite information we still have to use later on.
     */
    if (immediate == ARM_REG_R2)
    {
      if (value != ARM_REG_R1)
      {
        ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R1, immediate, 0, ARM_CONDITION_AL);
        immediate = ARM_REG_R1;
      }
      else
      {
        ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R3, immediate, 0, ARM_CONDITION_AL);
        immediate = ARM_REG_R3;
      }
    }
    ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R2, value, 0, ARM_CONDITION_AL);
  }

  /* As second argument we pass the offset (which is either encoded as an immediate or present in a register) */
  if (ARM_INS_FLAGS(orig_ins) & FL_IMMED)
  {
    ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R1, ARM_REG_NONE, 0, ARM_CONDITION_AL);
    ArmMakeConstantProducer(arm_ins, ARM_INS_IMMEDIATE(orig_ins));
  }
  else if (immediate != ARM_REG_R1)
    ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R1, immediate, 0, ARM_CONDITION_AL);

  /* We want the address of the base register in r0, so we can write to it if necessary. If the base is the stack pointer,
   * we will put the address of the stack pointer in the global_state.regs struct into r0. If not, the contents of the base
   * register have been pushed are now at the top of the stack. Moving the value of the stack pointer to r0 should suffice.
   */
  if (base == ARM_REG_R13)
  {
    /* Produce the address of the stored SP in the state struct */
    ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R0, ARM_REG_NONE, 0, ARM_CONDITION_AL);
    t_reloc* reloc = RelocTableAddRelocToRelocatable(
        OBJECT_RELOC_TABLE(obj),
        AddressNullForObject(obj), /* addend */
        T_RELOCATABLE(arm_ins), /* from */
        AddressNullForObject(obj),  /* from-offset */
        SYMBOL_BASE(global_state_sym), /* to */
        AddressAdd(SYMBOL_OFFSET_FROM_START(global_state_sym), AddressNewForObject(obj, 16 * adr_size)), /* to-offset */
        FALSE, /* hell */
        NULL, /* edge*/
        NULL, /* corresp */
        NULL, /* sec */
        "R00A00+" "\\" WRITE_32);
    ArmInsMakeAddressProducer(arm_ins, 0 /* immediate */, reloc);
  }
  else
    ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R0, ARM_REG_R13, 0, ARM_CONDITION_AL);

  /* The fourth argument is the flags */
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R3, ARM_REG_NONE, ARM_INS_FLAGS(orig_ins), ARM_CONDITION_AL);

  /* Backup the flags */
  if (save_cond)
    ArmMakeInsForBbl(Mrs, Append, arm_ins, bbl, isThumb, cond_reg, ARM_CONDITION_AL);

  /* Do the actual call */
  ArmMakeInsForBbl(CondBranchAndLink, Append, arm_ins, bbl, isThumb, ARM_CONDITION_AL);

  /* Restore all live registers */
  ArmMakeInsForBbl(Pop, Prepend, arm_ins, bbl_split, isThumb, regs, ARM_CONDITION_AL, isThumb);

  /* Take care of alignment if necessary, and pop the - potentially - changed register back (unless when it's the stack pointer!) */
  if ((aligned && base != ARM_REG_R13) || (!aligned && base == ARM_REG_R13))
    ArmMakeInsForBbl(Add, Prepend, arm_ins, bbl_split, isThumb, ARM_REG_R13, ARM_REG_R13, ARM_REG_NONE, adr_size, ARM_CONDITION_AL);/* Reclaim the stack space */
  if (base != ARM_REG_R13)
    ArmMakeInsForBbl(Pop, Prepend, arm_ins, bbl_split, isThumb, (1 << base), ARM_CONDITION_AL, isThumb);

  /* Restore the flags */
  if (save_cond)
    ArmMakeInsForBbl(Msr, Prepend, arm_ins, bbl_split, isThumb, cond_reg, ARM_CONDITION_AL, TRUE);

  /* Kill the fallthrough edge that was created by BblSplitBlock, and create the edges for the call/return to function_ldr */
  CfgEdgeKill(BBL_SUCC_FIRST(bbl));
  CfgEdgeCreateCall(cfg, bbl, FUNCTION_BBL_FIRST(function_str), bbl_split, FunctionGetExitBlock(function_str));

  /* Remove the instruction now that it has been replaced by a function call */
  InsKill(T_INS(orig_ins));
}

void SelfDebuggingTransformer::TransformLdm(t_bbl* bbl, t_arm_ins* orig_ins)
{
  /* Get some information about the instruction to replace and split its BBL in front of it */
  t_bool isThumb = ArmBblIsThumb(bbl);
  t_reg addr = ARM_INS_REGB(orig_ins);
  t_regset regs_to_load = RegsetNewFromUint32(ARM_INS_IMMEDIATE(orig_ins));
  t_uint32 nr_of_regs_to_load = RegsetCountRegs(regs_to_load);
  t_arm_condition_code condition = ARM_INS_CONDITION(orig_ins);
  t_bbl* bbl_split = BblSplitBlock(bbl, T_INS(orig_ins), TRUE);

  /* In case the instruction is conditional, we need to do some more splitting */
  t_arm_ins* arm_ins;
  if (condition != ARM_CONDITION_AL)
  {
    /* Append a conditional jump to bbl. This will fall through onto the split off BBL, and jump to
     * another BBL created in between these two BBLs that contains the conditional instructions.
     */
    ArmMakeInsForBbl(CondBranch, Append, arm_ins, bbl, isThumb, condition);

    /* This BBL will contain the conditional instructions */
    t_bbl* tmp = BblSplitBlock(bbl, T_INS(arm_ins), FALSE);
    CFG_EDGE_SET_CAT(BBL_SUCC_FIRST(bbl), ET_JUMP);/* Make the fallthrough edge created into a jump edge */

    /* tmp2 is the original bbl_split and will be our fallthrough if the condition is not satisfied. The
     * bbl_split bbl will contain more conditional instructions. */
    t_bbl* tmp2 = BblSplitBlock(bbl_split, BBL_INS_FIRST(bbl_split), TRUE);
    CFG_EDGE_SET_CAT(BBL_SUCC_FIRST(bbl_split), ET_JUMP);/* Make the fallthrough edge created into a jump edge */
    ArmMakeInsForBbl(UncondBranch, Append, arm_ins, bbl_split, isThumb);

    CfgEdgeCreate (cfg, bbl, tmp2, ET_FALLTHROUGH);

    /* We will start appending instructions to this newly created BBL */
    bbl = tmp;
  }

  /* The Ldm will be replaced by the following code:
   * PUSH ALL_LIVE_CALLER_SAVED
   * SUB SP, SP, #space_to_reserve (this depends on the alignment and the nr of regs we have to load)
   * [OPTIONAL] MOV R0, addr (move the addr register to r0, depending on whether or not it is already r0)
   * MOV R1, SP (now we have the address of the reserved space on the stack as second argument)
   * MOV R2, #nr_of_regs_to_load
   * [OPTIONAL] MRS cond_reg
   * BL function_ldm
   * [OPTIONAL] MSR cond_reg
   * POP REGS_TO_LOAD
   * [OPTIONAL] ADD SP, SP, #4 (depending on alignment)
   * POP ALL_LIVE_CALLER_SAVED
   * [OPTIONAL] ADD addr, addr, #adr_size * nr_of_regs_to_load (only if writeback flag is set)
   */

  /* Find all the caller-saved registers that are live and thus need to be saved and restored when inserting a call */
  t_regset regs_live = RegsetIntersect(CFG_DESCRIPTION(cfg)->callee_may_change, InsRegsLiveBefore(T_INS(orig_ins)));
  t_regset int_to_push = RegsetIntersect(CFG_DESCRIPTION(cfg)->int_registers, regs_live);
  t_regset cond_to_push = RegsetIntersect(CFG_DESCRIPTION(cfg)->cond_registers, regs_live);
  t_bool save_cond = !RegsetIsEmpty(cond_to_push);
  RegsetSetSubReg(int_to_push, ARM_REG_R15);
  t_reg cond_reg = ARM_REG_R4;/* A callee-saved register */
  if (save_cond)
    RegsetSetAddReg(int_to_push, cond_reg);
  RegsetDiff(int_to_push, regs_to_load);

  /* If the stack is not aligned with this push, we will align it later on in the next push */
  t_uint32 nr_of_regs_pushed = RegsetCountRegs(int_to_push);
  t_bool aligned = ((nr_of_regs_pushed % 2) == 0);

  /* Backup all live registers */
  t_uint32 regs = RegsetToUint32(int_to_push);
  ArmMakeInsForBbl(Push, Append, arm_ins, bbl, isThumb, regs, ARM_CONDITION_AL, isThumb);

  /* Calculate how many space we need to reserve on the stack and reserve it */
  t_uint32 space_to_reserve = adr_size * (aligned ? nr_of_regs_to_load : nr_of_regs_to_load + 1);
  ArmMakeInsForBbl(Sub, Append, arm_ins, bbl, isThumb, ARM_REG_R13, ARM_REG_R13, ARM_REG_NONE, space_to_reserve, ARM_CONDITION_AL);

  /* Move the address from which we want to load into r0 if necessary. If it's in R13, the TransformUseOfSP will take care of it */
  if (addr != ARM_REG_R0)
  {
    ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R0, addr, 0, ARM_CONDITION_AL);
    TransformUseOfSP (bbl, arm_ins);
  }

  /* Now put the SP in r1 so it can serve as the second argument */
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R1, ARM_REG_R13, 0, ARM_CONDITION_AL);

  /* The third argument is the number of registers we wish to load */
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R2, ARM_REG_NONE, nr_of_regs_to_load, ARM_CONDITION_AL);

  /* Backup the flags */
  if (save_cond)
    ArmMakeInsForBbl(Mrs, Append, arm_ins, bbl, isThumb, cond_reg, ARM_CONDITION_AL);

  /* Do the actual call */
  ArmMakeInsForBbl(CondBranchAndLink, Append, arm_ins, bbl, isThumb, ARM_CONDITION_AL);

  /* If the base register has to be updated, do this now, unless the it was one of the loaded registers */
  if ((ARM_INS_FLAGS(orig_ins) & FL_WRITEBACK) && !RegsetIn(regs_to_load, addr))
  {
    ArmMakeInsForBbl(Add, Prepend, arm_ins, bbl_split, isThumb, addr, addr, ARM_REG_NONE, adr_size * nr_of_regs_to_load, ARM_CONDITION_AL);
    TransformUseOfSP (bbl_split, arm_ins);
  }

  /* Restore all live registers */
  ArmMakeInsForBbl(Pop, Prepend, arm_ins, bbl_split, isThumb, regs, ARM_CONDITION_AL, isThumb);

  if (!aligned)
    ArmMakeInsForBbl(Add, Prepend, arm_ins, bbl_split, isThumb, ARM_REG_R13, ARM_REG_R13, ARM_REG_NONE, adr_size, ARM_CONDITION_AL);/* Reclaim the stack space */

  t_bool load_pc = RegsetIn(regs_to_load, ARM_REG_R15);
  if (load_pc)
  {
    RegsetSetSubReg(regs_to_load, ARM_REG_R15);
    ArmMakeInsForBbl(Str, Prepend, arm_ins, bbl_split, isThumb, ARM_REG_R0, ARM_REG_R1, ARM_REG_NONE, 0, ARM_CONDITION_AL, TRUE, TRUE, FALSE);

    /* Produce the address of the 'address' field in the state struct */
    ArmMakeInsForBbl(Mov, Prepend, arm_ins, bbl_split, isThumb, ARM_REG_R1, ARM_REG_NONE, 0, ARM_CONDITION_AL);
    t_reloc* reloc = RelocTableAddRelocToRelocatable(
        OBJECT_RELOC_TABLE(obj),
        AddressNullForObject(obj), /* addend */
        T_RELOCATABLE(arm_ins), /* from */
        AddressNullForObject(obj),  /* from-offset */
        SYMBOL_BASE(global_state_sym), /* to */
        SYMBOL_OFFSET_FROM_START(global_state_sym), /* to-offset */
        FALSE, /* hell */
        NULL, /* edge*/
        NULL, /* corresp */
        NULL, /* sec */
        "R00A00+" "\\" WRITE_32);
    ArmInsMakeAddressProducer(arm_ins, 0 /* immediate */, reloc);

    ArmMakeInsForBbl(Pop, Prepend, arm_ins, bbl_split, isThumb, 1 << ARM_REG_R0, ARM_CONDITION_AL, isThumb);
  }

  ArmMakeInsForBbl(Pop, Prepend, arm_ins, bbl_split, isThumb, RegsetToUint32(regs_to_load), ARM_CONDITION_AL, isThumb);

  /* Restore the flags */
  if (save_cond)
    ArmMakeInsForBbl(Msr, Prepend, arm_ins, bbl_split, isThumb, cond_reg, ARM_CONDITION_AL, TRUE);

  /* Kill the fallthrough edge that was created by BblSplitBlock, and create the edges for the call/return to function_ldr */
  CfgEdgeKill(BBL_SUCC_FIRST(bbl));
  CfgEdgeCreateCall(cfg, bbl, FUNCTION_BBL_FIRST(function_ldm), bbl_split, FunctionGetExitBlock(function_ldm));

  /* Remove the instruction now that it has been replaced by a function call */
  InsKill(T_INS(orig_ins));
}

void SelfDebuggingTransformer::TransformStm(t_bbl* bbl, t_arm_ins* orig_ins)
{
  /* Get some information about the instruction to replace and split its BBL in front of it */
  t_bool isThumb = ArmBblIsThumb(bbl);
  t_reg addr = ARM_INS_REGB(orig_ins);
  t_regset regs_to_store = RegsetNewFromUint32(ARM_INS_IMMEDIATE(orig_ins));
  t_uint32 nr_of_regs_to_store = RegsetCountRegs(regs_to_store);
  t_arm_condition_code condition = ARM_INS_CONDITION(orig_ins);
  t_bbl* bbl_split = BblSplitBlock(bbl, T_INS(orig_ins), TRUE);

  /* In case the instruction is conditional, we need to do some more splitting */
  t_arm_ins* arm_ins;
  if (condition != ARM_CONDITION_AL)
  {
    /* Append a conditional jump to bbl. This will fall through onto the split off BBL, and jump to
     * another BBL created in between these two BBLs that contains the conditional instructions.
     */
    ArmMakeInsForBbl(CondBranch, Append, arm_ins, bbl, isThumb, condition);

    /* This BBL will contain the conditional instructions */
    t_bbl* tmp = BblSplitBlock(bbl, T_INS(arm_ins), FALSE);
    CFG_EDGE_SET_CAT(BBL_SUCC_FIRST(bbl), ET_JUMP);/* Make the fallthrough edge created into a jump edge */

    /* tmp2 is the original bbl_split and will be our fallthrough if the condition is not satisfied. The
     * bbl_split bbl will contain more conditional instructions. */
    t_bbl* tmp2 = BblSplitBlock(bbl_split, BBL_INS_FIRST(bbl_split), TRUE);
    CFG_EDGE_SET_CAT(BBL_SUCC_FIRST(bbl_split), ET_JUMP);/* Make the fallthrough edge created into a jump edge */
    ArmMakeInsForBbl(UncondBranch, Append, arm_ins, bbl_split, isThumb);

    CfgEdgeCreate (cfg, bbl, tmp2, ET_FALLTHROUGH);

    /* We will start appending instructions to this newly created BBL */
    bbl = tmp;
  }

  /* The Stm will be replaced by the following code:
   * [OPTIONAL] SUB addr, addr, #adr_size * nr_of_regs_to_store (only if writeback flag is set)
   * PUSH ALL_LIVE_CALLER_SAVED
   * [OPTIONAL] SUB SP, SP, #adr_size (depending on alignment)
   * PUSH REGS_TO_STORE
   * [OPTIONAL] MOV R0, addr (move the addr register to r0, depending on whether or not it is already r0)
   * MOV R1, SP (now we have the address of the reserved space on the stack as second argument)
   * MOV R2, #nr_of_regs_to_store
   * [OPTIONAL] MRS cond_reg
   * BL function_stm
   * [OPTIONAL] MSR cond_reg
   * ADD SP, SP, #space_to_reserve
   * POP ALL_LIVE_CALLER_SAVED
   */

  /* Find all the caller-saved registers that are live and thus need to be saved and restored when inserting a call */
  t_regset regs_live = RegsetIntersect(CFG_DESCRIPTION(cfg)->callee_may_change, InsRegsLiveBefore(T_INS(orig_ins)));
  t_regset int_to_push = RegsetIntersect(CFG_DESCRIPTION(cfg)->int_registers, regs_live);
  t_regset cond_to_push = RegsetIntersect(CFG_DESCRIPTION(cfg)->cond_registers, regs_live);
  t_bool save_cond = !RegsetIsEmpty(cond_to_push);
  RegsetSetSubReg(int_to_push, ARM_REG_R15);
  t_reg cond_reg = ARM_REG_R4;/* A callee-saved register */
  if (save_cond)
    RegsetSetAddReg(int_to_push, cond_reg);

  /* If the stack is not aligned with this push, we will align it later on in the next push */
  t_uint32 nr_of_regs_pushed = RegsetCountRegs(int_to_push);
  t_bool aligned = ((nr_of_regs_pushed % 2) == 0);

  /* If the base register has to be updated, do this now */
  if (ARM_INS_FLAGS(orig_ins) & FL_WRITEBACK)
  {
    ArmMakeInsForBbl(Sub, Append, arm_ins, bbl, isThumb, addr, addr, ARM_REG_NONE, adr_size * nr_of_regs_to_store, ARM_CONDITION_AL);
    TransformUseOfSP (bbl, arm_ins);
  }

  /* Backup all live registers */
  t_uint32 regs = RegsetToUint32(int_to_push);
  ArmMakeInsForBbl(Push, Append, arm_ins, bbl, isThumb, regs, ARM_CONDITION_AL, isThumb);

  /* Push the regs that are to be stored onto the stack and allocate an extra stack slot if required for alignment */
  t_uint32 space_to_reserve = adr_size * (aligned ? nr_of_regs_to_store : nr_of_regs_to_store + 1);
  if (!aligned)
    ArmMakeInsForBbl(Sub, Append, arm_ins, bbl, isThumb, ARM_REG_R13, ARM_REG_R13, ARM_REG_NONE, adr_size, ARM_CONDITION_AL);
  ArmMakeInsForBbl(Push, Append, arm_ins, bbl, isThumb, RegsetToUint32(regs_to_store), ARM_CONDITION_AL, isThumb);

  /* Move the address to which we want to store into r0 if necessary. If it's in R13, the TransformUseOfSP will take care of it */
  if (addr != ARM_REG_R0)
  {
    ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R0, addr, 0, ARM_CONDITION_AL);
    TransformUseOfSP (bbl, arm_ins);
  }

  /* Now put the SP in r1 so it can serve as the second argument */
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R1, ARM_REG_R13, 0, ARM_CONDITION_AL);

  /* The third argument is the number of registers we wish to store */
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, ARM_REG_R2, ARM_REG_NONE, nr_of_regs_to_store, ARM_CONDITION_AL);

  /* Backup the flags */
  if (save_cond)
    ArmMakeInsForBbl(Mrs, Append, arm_ins, bbl, isThumb, cond_reg, ARM_CONDITION_AL);

  /* Do the actual call */
  ArmMakeInsForBbl(CondBranchAndLink, Append, arm_ins, bbl, isThumb, ARM_CONDITION_AL);

  /* Restore all live registers */
  ArmMakeInsForBbl(Pop, Prepend, arm_ins, bbl_split, isThumb, regs, ARM_CONDITION_AL, isThumb);

  /* Clean up the stack */
  ArmMakeInsForBbl(Add, Prepend, arm_ins, bbl_split, isThumb, ARM_REG_R13, ARM_REG_R13, ARM_REG_NONE, space_to_reserve, ARM_CONDITION_AL);/* Reclaim the stack space */

  /* Restore the flags */
  if (save_cond)
    ArmMakeInsForBbl(Msr, Prepend, arm_ins, bbl_split, isThumb, cond_reg, ARM_CONDITION_AL, TRUE);

  /* Kill the fallthrough edge that was created by BblSplitBlock, and create the edges for the call/return to function_ldr */
  CfgEdgeKill(BBL_SUCC_FIRST(bbl));
  CfgEdgeCreateCall(cfg, bbl, FUNCTION_BBL_FIRST(function_stm), bbl_split, FunctionGetExitBlock(function_stm));

  /* Remove the instruction now that it has been replaced by a function call */
  InsKill(T_INS(orig_ins));
}

void SelfDebuggingTransformer::TransformUseOfSP(t_bbl* bbl, t_arm_ins* arm_ins)
{
  t_bool isThumb = ArmBblIsThumb(bbl);
  t_arm_ins* tmp_ins;

  /* If the SP is the destination, we will store its new value in the global state */
  if (ARM_INS_REGA(arm_ins) == ARM_REG_R13)
  {
    t_regset available = RegsetDiff(possible, InsRegsLiveAfter(T_INS(arm_ins)));
    t_uint32 nr_of_dead_regs = RegsetCountRegs(available);

    /* Select the registers to use and push/pop them if necessary */
    t_reg sp_reg = ARM_REG_NONE;
    t_reg adr_reg = ARM_REG_NONE;
    if (nr_of_dead_regs == 0)
    {
      sp_reg = ARM_REG_R0;
      adr_reg = ARM_REG_R1;

      ArmMakeInsForIns(Push, Before, tmp_ins, arm_ins, isThumb, (1 << sp_reg) | (1 << adr_reg), ARM_CONDITION_AL, isThumb);
      ArmMakeInsForIns(Pop, After, tmp_ins, arm_ins, isThumb, (1 << sp_reg) | (1 << adr_reg), ARM_CONDITION_AL, isThumb);
    }
    else if (nr_of_dead_regs == 1)
    {
      sp_reg = ARM_REG_R0;
      REGSET_FOREACH_REG(available, adr_reg)
        if(adr_reg != sp_reg) break;

      ArmMakeInsForIns(Push, Before, tmp_ins, arm_ins, isThumb, (1 << sp_reg), ARM_CONDITION_AL, isThumb);
      ArmMakeInsForIns(Pop, After, tmp_ins, arm_ins, isThumb, (1 << sp_reg), ARM_CONDITION_AL, isThumb);
    }
    else
    {
      REGSET_FOREACH_REG(available, sp_reg)
        break;
      REGSET_FOREACH_REG(available, adr_reg)
        if(adr_reg != sp_reg) break;
    }

    /* Store the adapted SP value to the state struct */
    ArmMakeInsForIns(Str, After, tmp_ins, arm_ins, isThumb, sp_reg, adr_reg, ARM_REG_NONE, 0, ARM_CONDITION_AL, TRUE, TRUE, FALSE);

    /* Produce the address of the stored SP in the state struct */
    ArmMakeInsForIns(Mov, After, tmp_ins, arm_ins, isThumb, adr_reg, ARM_REG_NONE, 0, ARM_CONDITION_AL);
    t_reloc* reloc = RelocTableAddRelocToRelocatable(
        OBJECT_RELOC_TABLE(obj),
        AddressNullForObject(obj), /* addend */
        T_RELOCATABLE(tmp_ins), /* from */
        AddressNullForObject(obj),  /* from-offset */
        SYMBOL_BASE(global_state_sym), /* to */
        AddressAdd(SYMBOL_OFFSET_FROM_START(global_state_sym), AddressNewForObject(obj, 16 * adr_size)), /* to-offset */
        FALSE, /* hell */
        NULL, /* edge*/
        NULL, /* corresp */
        NULL, /* sec */
        "R00A00+" "\\" WRITE_32);
    ArmInsMakeAddressProducer(tmp_ins, 0 /* immediate */, reloc);

    /* Replace the destination register */
    ARM_INS_SET_REGA(arm_ins, sp_reg);
  }

  /* If SP is one of the source operands, we will load find a register to load the value of SP in the global state to */
  if (ARM_INS_REGB(arm_ins) == ARM_REG_R13 || ARM_INS_REGC(arm_ins) == ARM_REG_R13)
  {
    t_regset available = RegsetDiff(possible, InsRegsLiveBefore(T_INS(arm_ins)));
    t_uint32 nr_of_dead_regs = RegsetCountRegs(available);

    /* Select the register to use and push/pop if necessary */
    t_reg sp_reg = ARM_REG_NONE;
    if (nr_of_dead_regs == 0)
    {
      sp_reg = ARM_REG_R0;

      ArmMakeInsForIns(Push, Before, tmp_ins, arm_ins, isThumb, (1 << sp_reg), ARM_CONDITION_AL, isThumb);
      ArmMakeInsForIns(Pop, After, tmp_ins, arm_ins, isThumb, (1 << sp_reg), ARM_CONDITION_AL, isThumb);
    }
    else
      REGSET_FOREACH_REG(available, sp_reg)
        break;

    /* Produce the address of the stored SP in the state struct */
    ArmMakeInsForIns(Mov, Before, tmp_ins, arm_ins, isThumb, sp_reg, ARM_REG_NONE, 0, ARM_CONDITION_AL);
    t_reloc* reloc = RelocTableAddRelocToRelocatable(
        OBJECT_RELOC_TABLE(obj),
        AddressNullForObject(obj), /* addend */
        T_RELOCATABLE(tmp_ins), /* from */
        AddressNullForObject(obj),  /* from-offset */
        SYMBOL_BASE(global_state_sym), /* to */
        AddressAdd(SYMBOL_OFFSET_FROM_START(global_state_sym), AddressNewForObject(obj, 16 * adr_size)), /* to-offset */
        FALSE, /* hell */
        NULL, /* edge*/
        NULL, /* corresp */
        NULL, /* sec */
        "R00A00+" "\\" WRITE_32);
    ArmInsMakeAddressProducer(tmp_ins, 0 /* immediate */, reloc);

    /* Load the current SP value */
    ArmMakeInsForIns(Ldr, Before, tmp_ins, arm_ins, isThumb, sp_reg, sp_reg, ARM_REG_NONE, 0, ARM_CONDITION_AL, TRUE, TRUE, FALSE);

    /* Replace the source register(s) */
    if (ARM_INS_REGB(arm_ins) == ARM_REG_R13)
        ARM_INS_SET_REGB(arm_ins, sp_reg);
    if (ARM_INS_REGC(arm_ins) == ARM_REG_R13)
        ARM_INS_SET_REGC(arm_ins, sp_reg);
  }

  /* Sometimes this function will create no-ops. Kill them */
  if (ArmInsIsNOOP(arm_ins))
    InsKill(T_INS(arm_ins));
}

static t_bool sd_split_helper_IsStartOfPartition(t_bbl* bbl)
{
  /* The BBL is part of only one SelfDebugging Region. This will get it */
  Region* region = NULL;
  Region* tmp = NULL;
  const SelfDebuggingAnnotationInfo* info;
  BBL_FOREACH_SELFDEBUGGING_REGION(bbl, tmp, info)
    region = tmp;

  t_cfg_edge* edge;
  BBL_FOREACH_PRED_EDGE(bbl, edge)
  {
    if(CfgEdgeIsForwardInterproc(edge))
      continue;

    /* Determine the head. This depends on whether or not the incoming edge is part of corresponding
     * pair of edges (e.g. call/return).
     */
    t_bbl* head = CFG_EDGE_CORR(edge) ? CFG_EDGE_HEAD(CFG_EDGE_CORR(edge)) : CFG_EDGE_HEAD(edge);

    /* Determine the second region */
    Region* region2 = NULL;
    BBL_FOREACH_SELFDEBUGGING_REGION(head, tmp, info)
      region2 = tmp;

    /* If the two regions differ, we must partition */
    if(region != region2)
      return TRUE;
  }

  /* If there are no changes in region, don't partition */
  return FALSE;
}

static t_bool sd_split_helper_CanMerge(t_bbl* bbl1, t_bbl* bbl2)
{
  /* Find the first region */
  Region* region1 = NULL;
  Region* tmp = NULL;
  const SelfDebuggingAnnotationInfo* info;
  BBL_FOREACH_SELFDEBUGGING_REGION(bbl1, tmp, info)
    region1 = tmp;

  /* Find the second region */
  Region* region2 = NULL;
  BBL_FOREACH_SELFDEBUGGING_REGION(bbl2, tmp, info)
    region2 = tmp;

  /* If both partitions are not in the same region, they can't be merged */
  return (region1 == region2);
}

/* Do some preparatory (AD-specific) work on the CFG before doing any transformations */
static void SelfDebuggingPrepCfg (t_cfg* cfg)
{
  /* Check for every BBL whether there is an annotation indicating it shouldn't be transformed. If this is
   * the case, we will remove it from all anti debugging regions it is part of.
   */
  t_bbl* bbl;
  CFG_FOREACH_BBL(cfg, bbl)
  {
    t_function* fun = BBL_FUNCTION(bbl);
    if (!fun)
      continue;

    /* Gather all anti debugging regions and whether they need to be removed */
    vector<Region*> sd_regions;
    bool remove = false;

    Region* region;
    const SelfDebuggingAnnotationInfo* info;
    BBL_FOREACH_SELFDEBUGGING_REGION(bbl, region, info)
    {
      sd_regions.push_back(region);

      /* If the BBL is part of a non-transform region, we should remove it from all regions */
      if (!info->transform)
        remove = true;
    }

    /* Don't need to do any more checks if there aren't any regions */
    if (sd_regions.empty())
      continue;

    /* If we encounter call edges, split off the call instruction and remove it from the anti debugging regions */
    t_cfg_edge* edge;
    BBL_FOREACH_SUCC_EDGE(bbl, edge)
    {
      if (CfgEdgeTestCategoryOr(edge, ET_CALL) && (BBL_NINS(bbl) != 1))
      {
        t_bbl* split = BblSplitBlock (bbl, BBL_INS_LAST(bbl), TRUE);
        for (auto region : sd_regions)
          BblRemoveFromRegion(region, split);
        break;
      }
    }

    if (remove)
    {
      for (auto region : sd_regions)
        BblRemoveFromRegion(region, bbl);
    }
  }

  /* Split all functions that have BBLs both in and out of an anti debugging region. After this function has
   * been called all anti debugging regions will exist out of functions that have no BBLs outside the region.
   */
  CfgPartitionFunctions(cfg, sd_split_helper_IsStartOfPartition, sd_split_helper_CanMerge);

  /* Recompute liveness */
  CfgComputeLiveness (cfg, CONTEXT_SENSITIVE);
  CfgComputeSavedChangedRegisters (cfg);
}

void SelfDebuggingTransformer::TransformObject()
{
  STATUS(START, ("Anti Debugging"));

  /* Get all these functions */
  function_ldm = BBL_FUNCTION(T_BBL(SYMBOL_BASE(ldm_sym)));
  function_ldr = BBL_FUNCTION(T_BBL(SYMBOL_BASE(ldr_sym)));
  function_stm = BBL_FUNCTION(T_BBL(SYMBOL_BASE(stm_sym)));
  function_str = BBL_FUNCTION(T_BBL(SYMBOL_BASE(str_sym)));

  /* Get the CFG and do some preparatory work on it */
  cfg = OBJECT_CFG(obj);
  SelfDebuggingPrepCfg(cfg);

  Region* region;
  SelfDebuggingAnnotationInfo *info;
  CFG_FOREACH_SELFDEBUGGING_REGION(cfg, region, info)
  {
    /* Transform all of these functions if possible */
    for (auto fun : RegionGetAllFunctions(region))
    {
      if (CanTransformFunction(fun))
      {
        /* Do some logging */
        t_const_string log_msg = "Moving function %s to debugger context.\n";
        t_const_string fun_name = FUNCTION_NAME(fun) ? FUNCTION_NAME(fun) : "without name";
        VERBOSE(0, (log_msg, fun_name));
        LOG(L_TRANSFORMS, log_msg, fun_name);
        info->successfully_applied = TRUE;/* At least a part of the annotated region will be moved to debugger context */

        /* Initialize some global values used in transforming a function */
        constant = transform_index + 1;
        constants.push_back(constant);

        /* Calculate the offset in the map where we will put the value of the KV-pair */
        t_uint32 offset = transform_index * map_entry_size + sizeof(t_uint32);/* The offset of the value in the map */

        /* Do the actual function transformation (transform_index will be incremented) */
        TransformFunction(fun, FALSE);

        /* Set the value in the map: we're using the offset of the function's entrypoint to a known position in
         * the binary. As known position we're using the map itself.
         */
        RelocTableAddRelocToRelocatable(OBJECT_RELOC_TABLE(obj),
            AddressNullForObject(obj), /* addend */
            T_RELOCATABLE(map_sec), /* from */
            AddressNewForObject(obj, offset), /* from-offset */
            T_RELOCATABLE(FUNCTION_BBL_FIRST(fun)), /* to */
            AddressNullForObject(obj), /* to-offset */
            FALSE, /* hell */
            NULL, /* edge */
            NULL, /* corresp */
            T_RELOCATABLE(map_sec), /* sec */
            "R00R01-" "\\" WRITE_32);
      }
    }
  }

  /* Set all the variables in the linked in object */
  SectionSetData32 (T_SECTION(SYMBOL_BASE(nr_of_entries_sym)), SYMBOL_OFFSET_FROM_START(nr_of_entries_sym), transform_index);

  /* Resize the mapping table now that we know its size */
  SECTION_SET_DATA(map_sec, Realloc (SECTION_DATA(map_sec), transform_index * map_entry_size));
  SECTION_SET_CSIZE(map_sec, transform_index * map_entry_size);

  for(t_uint32 iii = 0; iii < transform_index; iii++)
  {
    /* Set the key in the map, at the right offset */
    t_uint32 offset = iii * map_entry_size;
    SectionSetData32 (map_sec, AddressNewForObject(obj, offset), constants[iii]);
  }

  STATUS(STOP, ("Anti Debugging"));
}

void SelfDebuggingTransformer::AddForceReachables(vector<string>& reachable_vector)
{
  reachable_vector.push_back(SD_IDENTIFIER_PREFIX"Init");
  reachable_vector.push_back(SD_IDENTIFIER_PREFIX"Str");
  reachable_vector.push_back(SD_IDENTIFIER_PREFIX"Ldr");
  reachable_vector.push_back(SD_IDENTIFIER_PREFIX"Stm");
  reachable_vector.push_back(SD_IDENTIFIER_PREFIX"Ldm");
}
