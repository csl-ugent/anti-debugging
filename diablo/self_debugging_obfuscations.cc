/* AUTHORS:
 * Bert Abrath
 * Ilja Nevolin
 */

#include "self_debugging_obfuscations.h"

#include <algorithm>
#include <functional>
#include <iomanip>
#include <sstream>

using namespace std;

s_ins::s_ins(t_arm_ins* arm_ins)
  : ins(arm_ins), opc(ARM_INS_OPCODE(arm_ins)), A(ARM_INS_REGA(arm_ins)), B(ARM_INS_REGB(arm_ins)), C(ARM_INS_REGC(arm_ins)), immed(ARM_INS_IMMEDIATE(arm_ins)), neg_immed(!(ARM_INS_FLAGS(arm_ins)&FL_DIRUP))
{
}

static void printLBBL(t_regset& LBBL, string prefix)
{
  string str = "";
  t_reg tmpr;
  REGSET_FOREACH_REG(LBBL, tmpr) {
    if(tmpr < 13)
      str += "" + to_string(tmpr) + ", ";
  }
  VERBOSE(0, ("\t %s%s",prefix.c_str(), str.c_str()));
}

/* Decide upon the obfuscation method to use, based on general information such as the available registers and
 * whether we're dealing with an incoming or outgoing edge.
 */
void Obfus::choose_method(unique_ptr<Obfus>& obfus, const t_regset available, t_bool incoming_edge, ObfusData* data)
{
  t_uint32 nr_of_dead_regs = RegsetCountRegs(available);
  switch (nr_of_dead_regs)
  {
    default:
    case 1:
      {
        obfus.reset(new Obfus_m_segv_2(data, false));
        break;
      }
    case 0:
      {
        obfus.reset(new Obfus_m_segv_10(data, false));
        break;
      }
  }
}

void Obfus::encode_constant(t_object* obj, t_bbl* bbl, t_regset& available, t_uint32 adr_size, t_uint32 constant)
{
  /* We will append the following code:
   * [OPTIONAL] PUSH {R0, R1} (if there are no dead regs)
   * CONST const_reg, $constant
   * There are two options in which to get the constant on stack:
   * 1.: PUSH const_reg
   * 2.: STR const_reg [SP + 4] (no dead regs, R0 is const_reg)
   *     POP const_reg
   */
  t_bool isThumb = ArmBblIsThumb(bbl);
  t_uint32 nr_of_dead_regs = RegsetCountRegs(available);
  t_arm_ins* arm_ins;

  /* Find a dead register to produce the constant in. If we don't find one, push and pop a live reg */
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
}

void ObfusData::generate_addr_mapping(t_object* obj, t_relocatable* target, t_uint32 offset, t_section* map_sec)
{
  if (IS_MUTILATED_ADDR_MAPPING) {
    //this relocatable will store the migrated code fragements address into addr_mapping
    //but it will first mutilate it (storing only the lowest 2 bytes and then XOR with some value (e.g. 0x5050))

    stringstream sstream, sstreamops;
    sstream << "R01";
    sstreamops << "^";
    sstream << "i" << std::hex << std::setw(8) << std::setfill('0') << MUTILATION_MASK_ADR_MAP;
    sstreamops << "^";
    sstream << "R00";
    sstream << sstreamops.str() << "\\" << WRITE_32;
    VERBOSE(1,("generate_addr_mapping:  %s", sstream.str().c_str()));

    RelocTableAddRelocToRelocatable(OBJECT_RELOC_TABLE(obj),
        AddressNullForObject(obj), // addend
        T_RELOCATABLE(map_sec), // from  R01
        AddressNewForObject(obj, offset), // from-offset
        target, // to  R00
        AddressNullForObject(obj), // to-offset
        FALSE, // hell
        NULL, // edge
        NULL, // corresp
        T_RELOCATABLE(map_sec), // sec R01
        sstream.str().c_str()); //mutilated values inside the addr_mapping
    // we shall store offset(migrated_frag, addr_mapping) XOR MUTILATION_MASK_ADR_MAP --> this way only a part of solution is stored in mapping.
  }
  else
    RelocTableAddRelocToRelocatable(OBJECT_RELOC_TABLE(obj),
        AddressNullForObject(obj), /* addend */
        T_RELOCATABLE(map_sec), /* from */
        AddressNewForObject(obj, offset), /* from-offset */
        target, /* to */
        AddressNullForObject(obj), /* to-offset */
        FALSE, /* hell */
        NULL, /* edge */
        NULL, /* corresp */
        T_RELOCATABLE(map_sec), /* sec */
        "R00R01-" "\\" WRITE_32);
}

ObfusData::ObfusData(t_cfg* cfg)
  : cfg(cfg)
{
  /* Initialize RNG */
  rng = RNGCreateChild(RNGGetRootGenerator(), "sd_obf");

  //// constant propagation analysis /////
  ASSERT(ConstantPropagationInit(cfg), ("constant propagation init failed"));
  ConstantPropagation (cfg, CONTEXT_INSENSITIVE); // CONTEXT_SENSITIVE inter-BBL   CONTEXT_INSENSITIVE (only within BBL)
  OptUseConstantInformation(cfg, CONTEXT_INSENSITIVE);
  CfgRemoveDeadCodeAndDataBlocks (cfg);

  generate_instruction_maps();
}

bool ObfusData::is_legal_branch(t_bbl* bbl, t_arm_ins* arm_ins)
{
  VERBOSE(2, ("\t xins: @G, type:%i %s, reg: %i",
        ARM_INS_CADDRESS(arm_ins),
        ARM_INS_TYPE(arm_ins),
        ARM_INS_OPCODE(arm_ins) == ARM_BLX ? "BLX" : "BX",
        ARM_INS_REGB(arm_ins)));

  if (BBL_CADDRESS(bbl) == 0 || ARM_INS_CADDRESS(arm_ins) == 0)
    return false;
  if (ARM_INS_REGB(arm_ins) == ARM_REG_R13 || ARM_INS_REGB(arm_ins) == ARM_REG_R15)
    return false;
  if (ARM_INS_IS_CONDITIONAL(arm_ins))
    return false;

  return true;
}

bool ObfusData::is_legal_loadstore(t_bbl* bbl, t_arm_ins* arm_ins)
{
  // All possible instructions are eg:  STR r0, r1           r0:=mem(r1)
  //                                    LDR r0, [r1, r2]     r0:=mem(r1+r2)
  //                                    LDR r0, [r1, r2]!    r0:=mem(r1+r2) and r1+=r2
  //                                    LDR r0, [r1, #4]!    r0:=mem(r1+r2) and r1+=0x4
  // Some of these instructions will not be allowed to ensure context switch happens.
  // The 2nd register in the above example (= rB) needs to be available to store an ill_addr.
  // The ill_addr will result in SIGSEGV when an LDR/STR is called.

  if (BBL_CADDRESS(bbl) == 0 || ARM_INS_CADDRESS(arm_ins) == 0)
    return false; //remove illegal bbls / ins

  if (ARM_INS_REGB(arm_ins) >= ARM_REG_R13)
    return false; //disallow LR, SP, PC, ... we shouldn't modify these registers.

  if (ARM_INS_IS_CONDITIONAL(arm_ins))
    return false; // if LDR/STR has a conditional express, it may not execute properly!

  if (ARM_INS_REGC(arm_ins) != ARM_REG_NONE)
    return false; // regC could make an ill_addr into a legal_addr and prevent SIGSEGV from happening
  // Since we don't know value of regC at this stage, we will have to disallow any LDR/STR with regC's.

  // An immed value 'can' also have the same effect, but luckily we do know immed's value at this stage.
  //if (obs->sins->immed == 0) return false; //testing to accept only ins with immediate values (<>0).

  //if (ARM_INS_FLAGS(arm_ins) & FL_WRITEBACK)
  //return false;// writeback check really necessary?? -> validate!
  // writeback should cause no harm because SIGSEGV happens before writeback happens.

  if (ARM_INS_IMMEDIATE(arm_ins) != 0)
    return false;

  return true;
}

void ObfusData::generate_instruction_maps()
{
  VERBOSE(1, ("-------- obfus_INS_Mapping start --------"));

  t_bbl* bbl;
  CFG_FOREACH_BBL(cfg, bbl) {
    t_function* fun = BBL_FUNCTION(bbl);
    if (!fun)
      continue;

    s_bbl* bbls_rw = new s_bbl();
    bbls_rw->bbl = bbl;
    bbls_rw->vsins = new vector<s_ins*>();

    s_bbl* bbls_x = new s_bbl();
    bbls_x->bbl = bbl;
    bbls_x->vsins = new vector<s_ins*>();

    t_ins* ins;
    BBL_FOREACH_INS(bbl, ins) {
      t_arm_ins* arm_ins = T_ARM_INS(ins);

      switch (ARM_INS_OPCODE(arm_ins)) {
        case ARM_LDR:		// ok
        case ARM_STR:		// ok
        case ARM_LDRB:		// ok
        case ARM_STRB: 		// ok
        case ARM_STRH: 		// ok
        case ARM_LDRH:		// ok
        case ARM_LDRSH:  	// untested: obfus map is empty ; tried bzip2
        case ARM_LDRSB: 	// untested: obfus map is empty ; tried bzip2
          //if (sins->neg_immed) //testing only negative immediates
          if (is_legal_loadstore(bbl, arm_ins))
            bbls_rw->vsins->push_back(new s_ins(arm_ins));
          //VERBOSE(0, ("\t%s r%i, r%i", ( opc == ARM_LDR ? "LDR" : "STR" ), regA, regB ));
          break;

        case ARM_BLX:
        case ARM_BX:
          if (is_legal_branch(bbl, arm_ins))
            bbls_x->vsins->push_back(new s_ins(arm_ins));
          break;

        case ARM_LDM: 	// not ok & deprecated ; read comment at 'obfus_is_legal_INS_LOAD_STORE_MANY'
        case ARM_STM: 	// not ok & deprecated ; read comment at 'obfus_is_legal_INS_LOAD_STORE_MANY'
          //VERBOSE(0, ("\t ins: @G, type:%s%i, regA: %i, regB: %i, regC: %i, immed: %i",ARM_INS_CADDRESS(arm_ins), (opc == ARM_LDM ? " LDM " : opc == ARM_STM ? " STM " : "     "),ARM_INS_TYPE(arm_ins),ARM_INS_REGA(arm_ins),ARM_INS_REGB(arm_ins),ARM_INS_REGC(arm_ins), ARM_INS_IMMEDIATE(arm_ins)));
          //if (obfus_is_legal_INS_LOAD_STORE_MANY(bbl, arm_ins))
          //	bbls->vsins->push_back(sins);
          //break;

        default:
          break;
      }
    }

    if (!bbls_rw->vsins->empty())
      ins_map_rw.push_back(bbls_rw);
    if (!bbls_x->vsins->empty())
      ins_map_x.push_back(bbls_x);
  }
  VERBOSE(1, ("BBLs in bbls_rw map: %i", ins_map_rw.size()));
  VERBOSE(1, ("BBLs in bbls_x map: %i", ins_map_x.size()));
  VERBOSE(1, ("-------- end --------"));
}


void ObfusData::delete_from_ins_map(vector<s_bbl*>& ins_map, s_bbl* sbbl, s_ins* sins)
{
  unsigned int posj = 0;
  for (; posj < sbbl->vsins->size(); posj++)
    if (sbbl->vsins->at(posj) == sins)
      break;
  ASSERT(posj < sbbl->vsins->size(), ("ERROR #1017"));
  sbbl->vsins->erase(sbbl->vsins->begin() + posj);

  if (sbbl->vsins->empty()) { // delete BBL from mapping when no more usable INS in vector
    unsigned int posi = 0;
    for (; posi < ins_map.size(); posi++)
      if (ins_map[posi] == sbbl)
        break;
    ASSERT(posi < ins_map.size(), ("ERROR #1012"));
    ins_map.erase(ins_map.begin() + posi);
  }
}

void ObfusData::intersect_available_and_mapped(t_regset& available, vector<s_bbl*>& ins_map, vector<s_bbl*>& vfil)
{
  // We look and fill the array with BBLs which have an instruction that can be used to result in SIGSEGV.
  vfil.clear();
  t_reg tmpr;
  printLBBL(available, "available regs: ");

  s_bbl* obs;
  for (unsigned int i = 0; i < ins_map.size(); i++) { //for every BBL ...
    obs = ins_map[i];
    for (unsigned int j = 0; j < obs->vsins->size(); j++) { //for every LDR/STR in the entire code...
      REGSET_FOREACH_REG(available, tmpr) {
        if (obs->vsins->at(j)->B == tmpr)// can we find an available register from current program state?
          vfil.push_back(obs); // yes, found!
      }
    }
  }
  VERBOSE(1, ("\t vfil count: %i", vfil.size()));
  //for (unsigned int i = 0; i < vfil.size(); i++)
  //VERBOSE(0, ("\t\t possible branch to ins: @G, bbl: @G  using regB: %i, regC: %i",ARM_INS_CADDRESS(vfil[i]->sins->ins), BBL_CADDRESS(vfil[i]->bbl), vfil[i]->sins->B, vfil[i]->sins->C));
}

t_arm_ins* Obfus_m_bkpt_1::encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target)
{
  // Create the breakpoint to switch to the debugger
  t_arm_ins* arm_ins;
  t_bool isThumb = ArmBblIsThumb(bbl);
  ArmMakeInsForBbl(Bkpt, Append, arm_ins, bbl, isThumb); //BKPT

  //om de liveness informatie van de aangemaakt BKPT instructie aan te passen zodat het CPSR register niet meer in de 'use' regset zit:
  t_regset regs_use = ARM_INS_REGS_USE(arm_ins);
  RegsetSetSubReg(regs_use, ARM_REG_CPSR);
  ARM_INS_SET_REGS_USE(arm_ins,regs_use);

  return arm_ins;
}

t_arm_ins* Obfus_m_fpe_1::encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target)
{
  ASSERT((RegsetCountRegs(available) >= 2), ("Can not use this signalling encoding: At least 2 available register(s) required!"));

  t_reg regX = ARM_REG_NONE, regY = ARM_REG_NONE;
  REGSET_FOREACH_REG(available, regX)
    if (regX <= ARM_REG_R12)
      break;
  RegsetSetSubReg(available, regX);
  REGSET_FOREACH_REG(available, regY)
    if (regX <= ARM_REG_R12)
      break;
  RegsetSetSubReg(available, regY);

  if (regX == ARM_REG_NONE || regY == ARM_REG_NONE)
    FATAL(("At least 2 avail. regs required"));

  VERBOSE(1, ("%i %i", regX, regY));

  // X = rand()%100    ;   Y = 0
  // X = X/Y  -> SIGFPE only if the machine supports the DIV operation and result isn't turned into zero.
  t_arm_ins* arm_ins;
  t_bool isThumb = ArmBblIsThumb(bbl);
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, regX, ARM_REG_NONE, RNGGenerateWithRange(data->rng, 0, 100), ARM_CONDITION_AL);
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, regY, ARM_REG_NONE, 0, ARM_CONDITION_AL);
  ArmMakeInsForBbl(Div, Append, arm_ins, bbl, isThumb, regX, regX, regY, 0, ARM_CONDITION_AL);

  return arm_ins;
}

t_arm_ins* Obfus_m_fpe_2::encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target)
{
  ASSERT((RegsetCountRegs(available) >= 2), ("Can not use this signalling encoding: At least 2 available register(s) required!"));

  t_reg regX = ARM_REG_NONE, regY = ARM_REG_NONE;
  REGSET_FOREACH_REG(available, regX)
    if (regX <= ARM_REG_R12)
      break;
  RegsetSetSubReg(available, regX);
  REGSET_FOREACH_REG(available, regY)
    if (regX <= ARM_REG_R12)
      break;
  RegsetSetSubReg(available, regY);

  if (regX == ARM_REG_NONE || regY == ARM_REG_NONE)
    FATAL(("At least 2 avail. regs required"));

  VERBOSE(1, ("%i %i", regX, regY));

  // X = 'offset'    ;   Y = 0
  // X = X/Y  -> SIGFPE only if the machine supports the DIV operation and result isn't turned into zero.
  t_arm_ins* arm_ins;
  bool isThumb = ArmBblIsThumb(bbl);
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, regX, ARM_REG_NONE, 0, ARM_CONDITION_AL);
  t_arm_ins* numerator_ins = arm_ins;
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, regY, ARM_REG_NONE, 0, ARM_CONDITION_AL);
  ArmMakeInsForBbl(Div, Append, arm_ins, bbl, isThumb, regX, regX, regY, 0, ARM_CONDITION_AL);
  t_arm_ins* div_ins = arm_ins;

  std::stringstream sstream;
  sstream << "iFFFFFFFF" << "R00R01^^";
  sstream << "\\" << WRITE_32;
  VERBOSE(1, ("%s", sstream.str().c_str()));
  t_reloc* reloc = RelocTableAddRelocToRelocatable(
      OBJECT_RELOC_TABLE(obj),
      AddressNullForObject(obj), /* addend */
      T_RELOCATABLE(numerator_ins), /* from */  // address produced here
      AddressNullForObject(obj),  /* from-offset */
      target, /* to */ // R00 confirmed
      AddressNullForObject(obj), /* to-offset */
      FALSE, /* hell */
      NULL, /* edge*/
      NULL, /* corresp */
      T_RELOCATABLE(div_ins), /* sec */ //R01 confirmed
      sstream.str().c_str());
  ArmInsMakeAddressProducer(numerator_ins, 0 /* immediate */, reloc);

  return div_ins;
}

bool Obfus_segv_abstract::obfus_is_legal_INS_LOAD_STORE_MANY(t_bbl* bbl, t_arm_ins* arm_ins)
{
  /*
     This method proved to be ineffective.
     Since 99% of all LDM and STM instructions have the SP register as base register (first operand).
     Register liveliness confirmed that the SP register is (almost never?) dead (available for us to use).
     So unless we perform a backup of the SP register (and restore it at the debugger's side), then this method is useless.
     Filling the SP register with an illegal address is not stealthy at all!!!
     */
  return false;
}

t_uint32 Obfus_m_segv_1::obfus_generate_random_ill_addr(t_uint32 immed, bool neg_immed)
{
  //    http://static.duartes.org/img/blogPosts/linuxFlexibleAddressSpaceLayout.png
  VERBOSE(1,("\t immed value:%i",immed));
  t_uint32 rnd, min, max;
  if (RNGGenerateBool(data->rng)) {
    min = 0x0;
    max = 0x8000;
  } else {                  // [ 0xC0000000, 0xFFFFFFFF [
    min = 0xC0000000;
    max = 0xFFFFFFFF;
  }
  rnd = RNGGenerateWithRange(data->rng, min, max);
  if (neg_immed && rnd - immed >= min && rnd - immed < max) {
    return rnd;
  } else if (!neg_immed && rnd + immed >= min && rnd + immed < max) {
    return rnd;
  } else {
    VERBOSE(1,("\t immed value:%i turned ill_addr into legal_addr, retrying...", immed));
    return obfus_generate_random_ill_addr(immed, neg_immed);
  }
}

void Obfus_m_segv_1::obfus_add_illegal_address(t_bbl* bbl, bool isThumb, t_reg regB, t_uint32 immed, bool neg_immed)
{
  // We have to store each byte in a separate variable,
  // because we cannot 'Mov' an immediate with more than 8 bits (1 byte);
  // although it is possible if it is "encodable", but not all values are encodable!
  // So we generate a random 32bit illegal address and split it into 4 bytes: A,B,C,D.
  // Finally we re-assemble the 32bit using "Add" instructions.
  //    https://alisdair.mcdiarmid.org/arm-immediate-value-encoding/

  t_arm_ins* arm_ins;
  t_uint32 X = obfus_generate_random_ill_addr(immed, neg_immed);
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, regB, ARM_REG_NONE, 0, ARM_CONDITION_AL);
  ArmMakeConstantProducer(arm_ins, X);

  /*t_uint32 A,B,C,D;
    A = X & 0xFF000000;
    B = X & 0xFF0000;
    C = X & 0xFF00;
    D = X & 0xFF;
  // Backup regextra
  t_reg regextra = (ARM_REG_R1 == regB ? ARM_REG_R2 : ARM_REG_R1 );
  ArmMakeInsForBbl(Push, Append, arm_ins, bbl, isThumb, 1<<regextra, ARM_CONDITION_AL, isThumb);

  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, regextra, ARM_REG_NONE, A, ARM_CONDITION_AL);
  ArmMakeInsForBbl(Add, Append, arm_ins, bbl, isThumb, regB, regextra, ARM_REG_NONE, 0, ARM_CONDITION_AL);

  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, regextra, ARM_REG_NONE, B, ARM_CONDITION_AL);
  ArmMakeInsForBbl(Add, Append, arm_ins, bbl, isThumb, regB, regextra, regB, 0, ARM_CONDITION_AL);

  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, regextra, ARM_REG_NONE, C, ARM_CONDITION_AL);
  ArmMakeInsForBbl(Add, Append, arm_ins, bbl, isThumb, regB, regextra, regB, 0, ARM_CONDITION_AL);

  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, regextra, ARM_REG_NONE, D, ARM_CONDITION_AL);
  ArmMakeInsForBbl(Add, Append, arm_ins, bbl, isThumb, regB, regextra, regB, 0, ARM_CONDITION_AL);

  // Restore regextra
  ArmMakeInsForBbl(Pop, Append, arm_ins, bbl, isThumb, 1<<regextra, ARM_CONDITION_AL, isThumb);
  VERBOSE(0, ("\t ill addr: %08X", A+B+C+D));
  */
}

t_regset Obfus_m_segv_1::obfus_get_used_registers_current_state(t_bbl* bbl)
{
  t_regset LBBL = BBL_REGS_LIVE_OUT(bbl);
  return LBBL;
}

void Obfus_m_segv_1::obfus_fill_stack_from_bbl(s_bbl* rbbl, s_ins* rsins, std::stack< std::pair<t_arm_ins*, s_bbl*> >& st)
{
  // We push all instructions of the BBL onto the stack, including the random LDR/STR (which may not be last in BBL).
  // The resulting stack can be processed bottom-up to find dummy instructions that can be allowed before reaching LDR/STR.
  t_arm_ins* tmparmins = NULL;
  t_ins* tmpins;
  _t_arm_opcode opc;
  while (true) {
    BBL_FOREACH_INS(rbbl->bbl, tmpins) {
      tmparmins = T_ARM_INS(tmpins);
      if (ARM_INS_CADDRESS(tmparmins) > 0) {
        opc = ARM_INS_OPCODE(tmparmins);

        VERBOSE(1, ("\t push onto stack: @G, type:%s%i, regA: %i, regB: %i, regC: %i, immed: %s%i",
              ARM_INS_CADDRESS(tmparmins), (opc == ARM_ADD ? " ADD " : opc == ARM_SUB ? " SUB " : "     "),
              ARM_INS_TYPE(tmparmins), ARM_INS_REGA(tmparmins),
              ARM_INS_REGB(tmparmins),
              ARM_INS_REGC(tmparmins),
              ARM_INS_FLAGS(tmparmins)&FL_DIRUP ? "+" :"-",
              ARM_INS_IMMEDIATE(tmparmins)));

        st.push( std::make_pair(tmparmins, rbbl));
      }
      if (tmparmins == rsins->ins)
        break;
    }
    if (tmparmins == rsins->ins)
      break;
    if (rbbl->next != 0)
      rbbl = rbbl->next;
    else
      break;
  }
  ASSERT(tmparmins == rsins->ins, ("error #802 at 'obfus_fill_stack_from_bbl' "));
}

bool Obfus_m_segv_1::obfus_process_stack_get_pairSplit_regB_check(std::pair<t_arm_ins*, s_bbl*>& pairSplit, s_ins* rsins)
{
  if (RegsetIn(ARM_INS_REGS_DEF(pairSplit.first), rsins->B))
    return false; // value (ill_addr) stored in regB may not be altered

  return true;
}

std::pair<t_arm_ins*, s_bbl*> Obfus_m_segv_1::obfus_process_stack_get_pairSplit(t_bbl* bbl, s_ins* rsins, t_regset& LBBL, std::stack< std::pair<t_arm_ins*, s_bbl*> >& st, vector<t_arm_ins*>& vfilINS)
{
  // Here we will process the stack and determine at which instruction we can split the BBL.
  // It is important that we allow as many dummy instructions as possible,
  // but also maintain our current program state, that may not be altered.
  // And the regB which holds the illegal encoded address may not be altered.

  vfilINS.clear();

  std::pair<t_arm_ins*, s_bbl*> pairSplit = st.top();
  vfilINS.push_back(pairSplit.first);
  st.pop();

  if (!enforceDummyInstructions)
    return pairSplit;

  while (!st.empty()) {

    if (ArmInsHasSideEffect( st.top().first ))
      break;                                                    // no stack mods allowed
    if (ArmInsIsSystemInstruction( st.top().first ))
      break;                                                    // no system instructions allowed
    if (!RegsetIsEmpty(RegsetIntersect(ARM_INS_REGS_DEF(st.top().first), LBBL)))
      break;                                                    // current state (LBBL) may not be altered by this instruction
    if (ARM_INS_IS_CONDITIONAL(st.top().first))
      break;                                                    // no conditional expressions allowed)
    if (ARM_INS_OPCODE(st.top().first) == ARM_B
        || ARM_INS_OPCODE(st.top().first) == ARM_BX
        || ARM_INS_OPCODE(st.top().first) == ARM_BLX
        || ARM_INS_OPCODE(st.top().first) == ARM_BL)
      break;                                                     // no branches allowed

    /*
       taken this situation, where r3 contains an ill_addr and our code jumped to 9540:
9540:       e5932048        ldr     r2, [r3, #72]   ; 0x48
9544:       e2822004        add     r2, r2, #4
9548:       e5832048        str     r2, [r3, #72]   ; 0x48
it is possible that SIGSEGV happens before the instruction we want;  => premature SIGSEGV!
we want it to happen at 9548, but it already happens at 9540;
so we disallow all instructions who try to load/store from the register (regB) that stores the ill_addr:
*/
    if (RegsetIn(ARM_INS_REGS_USE(st.top().first), rsins->B))
      break;
    /*
       taken this situation, where r3 is ill_addr  and our code jumped to 20474:
20474:       e59d2004        ldr     r2, [sp, #4]
20478:       e5922000        ldr     r2, [r2]
2047c:       e5921018        ldr     r1, [r2, #24]
20480:       e59d0010        ldr     r0, [sp, #16]
20484:       e59d2020        ldr     r2, [sp, #32]
20488:       e0622000        rsb     r2, r2, r0
2048c:       e0812002        add     r2, r1, r2
20490:       e5832018        str     r2, [r3, #24]
we jump to 20474 with, and run the dummy instructions
however, what if r2 is 0x0 -> this counts as an ill addr => premature SIGSEGV!
since we do now know the value of the registers, we can exclude all load instructions.
The same is true for all STR instructions; which may attempt to store into a register from an illegal address (eg 0x0).
*/


    // any intermediate (aka dummy instructions) which are load & store can cause SIGBUS/SIGSEGV, so we may not allow them:
    /*if (ARM_INS_OPCODE(st.top().first) == ARM_LDR || ARM_INS_OPCODE(st.top().first) == ARM_STR)
      break;*/
    if (      ARM_INS_TYPE(st.top().first) == IT_STORE
        ||  ARM_INS_TYPE(st.top().first) == IT_FLT_STORE
        ||  ARM_INS_TYPE(st.top().first) == IT_STORE_MULTIPLE
        ||  ARM_INS_TYPE(st.top().first) == IT_LOAD
        ||  ARM_INS_TYPE(st.top().first) == IT_FLT_LOAD
        ||  ARM_INS_TYPE(st.top().first) == IT_LOAD_MULTIPLE
       )
      break;


    if (onlySimpleDummyInstructions &&
        ARM_INS_OPCODE(st.top().first) != ARM_MOV &&
        ARM_INS_OPCODE(st.top().first) != ARM_ADD &&
        ARM_INS_OPCODE(st.top().first) != ARM_SUB)
      break;

    if (!obfus_process_stack_get_pairSplit_regB_check(st.top(), rsins))
      break;

    // move up by one instruction since it will do no harm to current program state.
    vfilINS.push_back(st.top().first); // passed INS
    pairSplit = st.top();
    st.pop();
  }
  std::reverse(vfilINS.begin(),vfilINS.end()); //preserve stack ordering
  return pairSplit;
}

pair<s_bbl*, s_bbl*> Obfus_m_segv_1::obfus_perform_split(std::pair<t_arm_ins*, s_bbl*>& pairSplit, bool force)
{
  s_bbl* rbbl = pairSplit.second;
  s_bbl* obbl = pairSplit.second;
  // split only if force OR (#ins > 1 and ins to split at isn't already first in BBL).
  if (force || (BBL_NINS( rbbl->bbl ) > 1 && T_ARM_INS(BBL_INS_FIRST( rbbl->bbl )) != pairSplit.first  ))
  {

    //find the correct rbbl, in case it has been split previously ::
    while (true) {
      t_ins* ins;
      BBL_FOREACH_INS(rbbl->bbl, ins) {
        if (ins == T_INS(pairSplit.first))
          break;
      }
      if (ins == T_INS(pairSplit.first))
        break;
      if (rbbl->next)
        rbbl = rbbl->next;
      else
        FATAL(("Something is terribly wrong with the code"));
    }

    VERBOSE(1, ("\t going to split on instr @G of BBL @G",ARM_INS_CADDRESS(pairSplit.first), BBL_CADDRESS(rbbl->bbl) ));
    t_bbl* tmp = BblSplitBlock(rbbl->bbl, T_INS(pairSplit.first), TRUE); //fallthrough edge created automatically

    s_bbl* bblNext = new s_bbl();
    bblNext->bbl = tmp;
    bblNext->vsins = rbbl->vsins;

    s_bbl* bblBackUp = rbbl->next;
    rbbl->next = bblNext;
    bblNext->next = bblBackUp;

    s_bbl* it = rbbl;//ins_map_rw[pos];
    while (it) {
      VERBOSE(1, ("\t bbl @G ; next %i",BBL_CADDRESS(it->bbl),(it->next)));
      it = it->next;
    }
    return make_pair(rbbl, bblNext); // <old, new>
  }
  return make_pair(obbl, rbbl); // <old, new>
}

std::pair<int, s_bbl*> Obfus_m_segv_1::obfus_prepare_rbbl(s_bbl* rbbl, s_ins* rsins, t_bbl* bbl, vector<t_arm_ins*>& vfilINS, std::pair<t_arm_ins*, s_bbl*>& pairSplit)
{
  if (T_ARM_INS(BBL_INS_FIRST(rbbl->bbl)) == rsins->ins) {
    if (enforceDummyInstructions)
      return std::make_pair(2, (s_bbl*)NULL);
    else
      VERBOSE(1, ("\t processing first ins in BBL."));
  } else { // we have to split rbbl->bbl so that we have a block with a LDR/STR instruction.
    VERBOSE(1, ("\t processing non-first ins in BBL."));
  }
  t_regset LBBL = obfus_get_used_registers_current_state(bbl);
  t_reg tmpr;
  printLBBL(LBBL, "LBBLs: ");

  std::stack< std::pair<t_arm_ins*, s_bbl*> > st;
  obfus_fill_stack_from_bbl(rbbl, rsins, st);
  if (st.empty()){
    return std::make_pair(2, (s_bbl*)NULL);
  }
  VERBOSE(1, ("\t before stack size:%i", st.size()));
  pairSplit = obfus_process_stack_get_pairSplit(rbbl->bbl, rsins, LBBL, st, vfilINS);
  VERBOSE(1, ("\t after stack size:%i", vfilINS.size()));
  if (vfilINS.size() == 1 && enforceDummyInstructions)
    return std::make_pair(2, (s_bbl*)NULL);  //if we wish to have at least one dummy instruction before the STR/LDR:
  else
    return std::make_pair(0, rbbl);
}

pair<s_bbl*, s_ins*> Obfus_m_segv_1::obfus_get_random_struct(vector<s_bbl*>& ins_map, vector<s_bbl*>& vfil, bool deleteFromVFIL)
{
  t_uint32 ri = RNGGenerateWithRange(data->rng, 0, vfil.size() -1);
  s_bbl* rbbl = vfil[ri]; //get random BBL
  ASSERT(!rbbl->vsins->empty() , ("WHOOPS"));
  if (deleteFromVFIL)
    vfil.erase(vfil.begin()+ri);

  t_uint32 rj = RNGGenerateWithRange(data->rng, 0, rbbl->vsins->size() -1);
  s_ins* rsins = rbbl->vsins->at(rj); // get random INS from BBL

  if (ARM_INS_CADDRESS(rsins->ins) == 0) {
    data->delete_from_ins_map(ins_map, rbbl, rsins); // do not re-use same <INS,BBL>
    return obfus_get_random_struct(ins_map, vfil, deleteFromVFIL);
  }

  if (delete_INS_BBL_FromMapping)
    data->delete_from_ins_map(ins_map, rbbl, rsins); // do not re-use same <INS,BBL>

  VERBOSE(1, ("\t random (%i) branch addr: @G ins: @G, regB: %i, regC: %i", ri, BBL_CADDRESS(rbbl->bbl),ARM_INS_CADDRESS(rsins->ins), rsins->B, rsins->C));

  return make_pair(rbbl, rsins);
}

short int Obfus_m_segv_1::obfus_process_rbbl(t_bbl* bbl, bool isThumb, s_bbl*& rbbl, s_ins* rsins, vector<t_arm_ins*>& vfilINS, pair<t_arm_ins*, s_bbl*>& pairSplit)
{
  std::pair<int, s_bbl*> ppair = obfus_prepare_rbbl(rbbl, rsins, bbl, vfilINS, pairSplit);
  VERBOSE(1, ("\t ppair %i", ppair.first));
  if (ppair.first == 2) {
    VERBOSE(1, ("\t recursion required...\n"));
    return 2; //recursion
  }  else {
    rbbl = ppair.second;
    return 0; //ok
  }
}

t_arm_ins* Obfus_m_segv_1::encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target)
{
  ASSERT(!data->ins_map_rw.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));
  ASSERT(!RegsetIsEmpty(available), ("Can not use this signalling encoding: At least 1 available register(s) required!"));

  vector<s_bbl*> vfil;
  data->intersect_available_and_mapped(available, data->ins_map_rw, vfil);
  ASSERT(!vfil.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));

  pair<s_bbl*, s_ins*> rpair;
  short int processi = 2;
  vector<t_arm_ins*> vfilINS;
  pair<t_arm_ins*, s_bbl*> pairSplit;
  t_arm_ins* arm_ins;
  bool isThumb = ArmBblIsThumb(bbl);
  while (processi != 0) {
    ASSERT(!vfil.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));
    rpair = obfus_get_random_struct(data->ins_map_rw, vfil, true);
    processi = obfus_process_rbbl(bbl, isThumb, rpair.first, rpair.second, vfilINS, pairSplit);
  }
  s_bbl* rbbl = rpair.first;
  s_ins* rsins = rpair.second;
  rbbl = obfus_perform_split(pairSplit, false).second;
  VERBOSE(1, ("\t jump to BBL @G",BBL_CADDRESS(rbbl->bbl)));
  // add instructions to alter regB and generate an ill_addr.
  obfus_add_illegal_address(bbl, isThumb, rsins->B, rsins->immed, rsins->neg_immed);

  // add a jump instruction.
  ArmMakeInsForBbl(UncondBranch, Append, arm_ins, bbl, isThumb);
  // finally create edge matching the jump instruction is CFG.
  t_uint32 edge_jump_type = rbbl->bbl == bbl ? ET_JUMP : ET_IPJUMP;
  CfgEdgeCreate(data->cfg, bbl, rbbl->bbl, edge_jump_type);
  VERBOSE(1, ("edge create %02X %02X", BBL_CADDRESS(bbl), BBL_CADDRESS(rbbl->bbl)));

  return rsins->ins;
}

t_arm_ins* Obfus_m_segv_2::encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target)
{
  /*
     Works quite similar to method_1 except that the ill_addr isn't a random number,
     but it actually encodes the offset between the ''instruction that will result in SIGSEGV'':=A and  ''the BBL that will be executed in the debugger's context'':=B.
     Encoding is done using XOR operations, formula:
     ill_addr_encoded_offset = ((A xor B) xor {immediate >= 0}) xor 0xFFFFFFFF

     the randomly chosen LDR/STR will attempt to load this ill_addr and result in a SIGSEGV.
     The Debugger will be able to load the ill_addr, since it is stored in a register; and it also knows A, since thats where SIGSEGV occured (the PC points to it),
     We can extract the immediate from A's hex value. These three known variables allow us to reconstruct B and change PC to B.
     */

  ASSERT(!data->ins_map_rw.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));
  ASSERT(!RegsetIsEmpty(available), ("Can not use this signalling encoding: At least 1 available register(s) required!"));

  vector<s_bbl*> vfil;
  data->intersect_available_and_mapped(available, data->ins_map_rw, vfil);
  ASSERT(!vfil.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));

  t_arm_ins* arm_ins;
  bool isThumb = ArmBblIsThumb(bbl);
  pair<s_bbl*, s_ins*> rpair;
  short int processi = 2;
  vector<t_arm_ins*> vfilINS;
  pair<t_arm_ins*, s_bbl*> pairSplit;
  while (processi != 0) {
    ASSERT(!vfil.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));
    rpair = obfus_get_random_struct(data->ins_map_rw, vfil, true);
    processi = obfus_process_rbbl(bbl, isThumb, rpair.first, rpair.second, vfilINS, pairSplit);
  }
  s_bbl* rbbl = rpair.first;
  s_ins* rsins = rpair.second;
  rbbl = obfus_perform_split(pairSplit, false).second;
  VERBOSE(1, ("\t jump to BBL @G",BBL_CADDRESS(rbbl->bbl)));

  //ArmMakeInsForBbl(Noop, Append, arm_ins, bbl, isThumb); // add Nop to make searching in asm easier !!! remove in production !!!
  // create dummy 'mov' which will be changed by AddressProducer into an ill_addr_encoded_offset.
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, rsins->B, ARM_REG_NONE, 0, ARM_CONDITION_AL);
  t_arm_ins* ill_ins_encoded = arm_ins; // the AddressProducer will use this instruction to store the ill_addr_encoded_offset.
  t_arm_ins* ins_LDR_STR = rsins->ins; // *from* this instruction, the offset will be calculated, to *to* migrated fragment.

  // add a jump instruction.
  ArmMakeInsForBbl(UncondBranch, Append, arm_ins, bbl, isThumb);
  // finally create edge matching the jump instruction is CFG.
  t_uint32 edge_jump_type = rbbl->bbl == bbl ? ET_JUMP : ET_IPJUMP;
  CfgEdgeCreate(data->cfg, bbl, rbbl->bbl, edge_jump_type);

  std::stringstream sstream, sstreamops, simmed; //encode immed value into 32bit hex value (8 hex chars).
  simmed  << "i" << std::hex << std::setw(8) << std::setfill('0') << rsins->immed;
  sstream << simmed.str() << "iFFFFFFFF" << "R00R01";
  sstreamops << "^^";
  if (rsins->neg_immed)
    sstreamops << "+";
  else
    sstreamops << "_";
  sstream << sstreamops.str() << "\\" << WRITE_32;
  VERBOSE(1, ("%s", sstream.str().c_str()));

  t_reloc* reloc = RelocTableAddRelocToRelocatable(
      OBJECT_RELOC_TABLE(obj),
      AddressNullForObject(obj), /* addend */
      T_RELOCATABLE(ill_ins_encoded), /* from */  // address produced here
      AddressNullForObject(obj),  /* from-offset */
      target, /* to */ // R00 confirmed
      AddressNullForObject(obj), /* to-offset */
      FALSE, /* hell */
      NULL, /* edge*/
      NULL, /* corresp */
      T_RELOCATABLE(ins_LDR_STR), /* sec */ //R01 confirmed
      sstream.str().c_str());
  ArmInsMakeAddressProducer(ill_ins_encoded, 0 /* immediate */, reloc);

  return ins_LDR_STR;
}

t_arm_ins* Obfus_m_segv_3::encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target)
{
  /*
     Works quite similar to method_2
     except that we will not bother using a random LDR/STR, but insert our own.
     This decreases complexity/obfuscation but the overhead is lower, thus overall performance is a bit higher.
     */

  ASSERT(!data->ins_map_rw.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));
  ASSERT(!RegsetIsEmpty(available), ("Can not use this signalling encoding: At least 1 available register(s) required!"));

  // look for an available register: regB which will hold the ill_addr_encoded_offset.
  t_reg regB = ARM_REG_NONE;
  REGSET_FOREACH_REG(available, regB)
    if (regB <= ARM_REG_R12)
      break;

  // when not a single register is available; and we shouldn't push, since we cannot know if we'll have to pop in debugger.
  ASSERT(!(regB == ARM_REG_NONE || regB > ARM_REG_R12), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));

  //ArmMakeInsForBbl(Noop, Append, arm_ins, bbl, isThumb); // add Nop to make searching in asm easier !!! remove in production !!!
  // create dummy 'mov' which will be changed by AddressProducer into an ill_addr_encoded_offset.
  t_arm_ins* arm_ins;
  bool isThumb = ArmBblIsThumb(bbl);
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, regB, ARM_REG_NONE, 0, ARM_CONDITION_AL);
  t_arm_ins* ill_ins_encoded = arm_ins; // the AddressProducer will use this instruction to store the ill_addr_encoded_offset.

  // add LDR/STR instruction
  if (RNGGenerateBool(data->rng)) {
    ArmMakeInsForBbl(Str, Append, arm_ins, bbl, isThumb, RNGGenerateWithRange(data->rng, ARM_REG_R0, ARM_REG_R12), regB, ARM_REG_NONE, 0, ARM_CONDITION_AL, FALSE /* pre */, FALSE /* up */, FALSE /* wb */);
  } else {
    ArmMakeInsForBbl(Ldr, Append, arm_ins, bbl, isThumb, RNGGenerateWithRange(data->rng, ARM_REG_R0, ARM_REG_R12), regB, ARM_REG_NONE, 0, ARM_CONDITION_AL, FALSE /* pre */, FALSE /* up */, FALSE /* wb */);
  }
  ARM_INS_SET_REGC(arm_ins, ARM_REG_NONE);
  ARM_INS_SET_IMMEDIATE(arm_ins, 0);

  t_arm_ins* ins_LDR_STR = arm_ins; // *from* this instruction, the offset will be calculated, to *to* migrated fragment.


  std::stringstream sstream, sstreamops; //encode immed value into 32bit hex value (8 hex chars).
  sstream <<  "iFFFFFFFF" << "R00R01";
  sstreamops << "^^";
  sstream << sstreamops.str() << "\\" << WRITE_32;
  VERBOSE(1, ("%s", sstream.str().c_str()));


  t_reloc* reloc = RelocTableAddRelocToRelocatable(
      OBJECT_RELOC_TABLE(obj),
      AddressNullForObject(obj), /* addend */
      T_RELOCATABLE(ill_ins_encoded), /* from */  // address produced here
      AddressNullForObject(obj),  /* from-offset */
      target, /* to */ // R00 confirmed
      AddressNullForObject(obj), /* to-offset */
      FALSE, /* hell */
      NULL, /* edge*/
      NULL, /* corresp */
      T_RELOCATABLE(ins_LDR_STR), /* sec */ //R01 confirmed
      sstream.str().c_str());
  ArmInsMakeAddressProducer(ill_ins_encoded, 0 /* immediate */, reloc);

  return ins_LDR_STR;
}

void Obfus_m_segv_4::obfus_do_const_analysis(t_bbl* bbl, vector<pair<t_reg, t_uint32>>& vregConst)
{
  vregConst.clear();
  t_procstate* procstate = BBL_PROCSTATE_IN( bbl ); // analyse this bbl
  ASSERT(procstate != NULL, ("procstate is null; diabloanopt_constprop.c comment out the last foreach loop line #1537 - #1543."));
  t_register_content c;
  for (t_reg reg = ARM_REG_R0; reg <= ARM_REG_R15; reg++) {
    auto reg_level = ProcStateGetReg(procstate, reg, &c);
    if (reg_level != CP_BOT && reg_level != CP_TOP) {
      t_reloc *rel;
      auto tag_level = ProcStateGetTag(procstate, reg, &rel);
      if (tag_level != CP_BOT && tag_level != CP_TOP) { // dit register bevat een tag (=uitkomst van relocatie)
        //VERBOSE(0, ("\tanalysis<1> R%i tag := %02X", reg, AddressExtractUint32(c.i)));
      } else { // dit register bevat een constante
        //VERBOSE(0, ("\tanalysis<2> R%i := %02X", reg, AddressExtractUint32(c.i)));
        if (AddressExtractUint32(c.i) > 0)
          vregConst.push_back(make_pair(reg, AddressExtractUint32(c.i)));
      }
    }
  }

}

bool Obfus_m_segv_4::obfus_process_stack_get_pairSplit_regB_check(std::pair<t_arm_ins*, s_bbl*>& pairSplit, s_ins* rsins)
{
  t_arm_ins* LDR_STR = rsins->ins;
  if (RegsetIn(ARM_INS_REGS_DEF(pairSplit.first), rsins->B)) {

    //if (ARM_INS_OPCODE(pairSplit.first) == ARM_ADD || ARM_INS_OPCODE(pairSplit.first) == ARM_SUB) {

    vector<pair<t_reg, t_uint32>> vregConst;
    obfus_do_const_analysis(pairSplit.second->bbl, vregConst);
    VERBOSE(1, ("vregConst size: %i", vregConst.size()));

    bool rB = false, rC = false;
    for (unsigned int i = 0; i < vregConst.size(); i++) {

      VERBOSE(1, ("\t vregConst[i] := %02X", vregConst[i].second));

      VERBOSE(1, ("\t r%i   =?  r%i",vregConst[i].first, ARM_INS_REGB(LDR_STR)));
      if (rB == false && vregConst[i].first == ARM_INS_REGB(LDR_STR))
        rB = true;

      VERBOSE(1, ("\t r%i   =?  r%i",vregConst[i].first, ARM_INS_REGC(LDR_STR)));
      if (rC == false && (vregConst[i].first == ARM_INS_REGC(LDR_STR) || ARM_REG_NONE == ARM_INS_REGC(LDR_STR)))
        rC = true; //could be immediate as well

    }
    if (rB == false || rC == false)
      return false;
    else
      return true;
  }
  // }

  return true;
}

t_arm_ins* Obfus_m_segv_4::encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target)
{
  ASSERT(!data->ins_map_rw.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));
  ASSERT(!RegsetIsEmpty(available), ("Can not use this signalling encoding: At least 1 available register(s) required!"));

  vector<s_bbl*> vfil;
  data->intersect_available_and_mapped(available, data->ins_map_rw, vfil);
  ASSERT(!vfil.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));

  vector<pair<t_reg, t_uint32>> vregConst;
  vector<s_bbl*>::iterator it = vfil.begin();
  while(it != vfil.end()) {
    obfus_do_const_analysis((*it)->bbl, vregConst);
    if (vregConst.empty()) {
      it = vfil.erase(it); //allow only BBLs that have a known CTE reg
    } else {
      VERBOSE(1, ("\t\t vregConst.size() := %i", vregConst.size()));
      ++it;
    }
  }
  VERBOSE(1, ("\t m4 vfil size: %i", vfil.size()));

  t_arm_ins* arm_ins;
  bool isThumb = ArmBblIsThumb(bbl);
  pair<s_bbl*, s_ins*> rpair;
  short int processi = 2;
  vector<t_arm_ins*> vfilINS;
  pair<t_arm_ins*, s_bbl*> pairSplit;
  while (processi != 0) {
    ASSERT(!vfil.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));
    rpair = obfus_get_random_struct(data->ins_map_rw, vfil, true);
    processi = obfus_process_rbbl(bbl, isThumb, rpair.first, rpair.second, vfilINS, pairSplit);
  }
  s_bbl* rbbl = rpair.first;
  s_ins* rsins = rpair.second;
  rbbl = obfus_perform_split(pairSplit, false).second;
  VERBOSE(1, ("\t jump to BBL @G",BBL_CADDRESS(rbbl->bbl)));

  //ArmMakeInsForBbl(Noop, Append, arm_ins, bbl, isThumb); // add Nop to make searching in asm easier !!! remove in production !!!
  // create dummy 'mov' which will be changed by AddressProducer into an ill_addr_encoded_offset.
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, rsins->B, ARM_REG_NONE, 0, ARM_CONDITION_AL);
  t_arm_ins* ill_ins_encoded = arm_ins; // the AddressProducer will use this instruction to store the ill_addr_encoded_offset.
  t_arm_ins* ins_LDR_STR = rsins->ins; // *from* this instruction, the offset will be calculated, to *to* migrated fragment.

  // add a jump instruction.
  ArmMakeInsForBbl(UncondBranch, Append, arm_ins, bbl, isThumb);
  // finally create edge matching the jump instruction is CFG.
  t_uint32 edge_jump_type = rbbl->bbl == bbl ? ET_JUMP : ET_IPJUMP;
  CfgEdgeCreate(data->cfg, bbl, rbbl->bbl, edge_jump_type);


  std::stringstream sstream, simmed;
  simmed  << "i" << std::hex << std::setw(8) << std::setfill('0') << rsins->immed;
  sstream << simmed.str() << "iFFFFFFFF" << "R00R01^^";
  if (rsins->neg_immed)
    sstream << "+";
  else
    sstream << "_";
  sstream << "\\" << WRITE_32;
  VERBOSE(1, (sstream.str().c_str()));


  t_reloc* reloc = RelocTableAddRelocToRelocatable(
      OBJECT_RELOC_TABLE(obj),
      AddressNullForObject(obj), // addend
      T_RELOCATABLE(ill_ins_encoded), // from   // address produced here
      AddressNullForObject(obj),  // from-offset
      target, // to  // R00 confirmed
      AddressNullForObject(obj), // to-offset
      FALSE, // hell
      NULL, // edge
      NULL, // corresp
      T_RELOCATABLE(ins_LDR_STR), // sec  //R01 confirmed
      sstream.str().c_str());
  ArmInsMakeAddressProducer(ill_ins_encoded, 0 , reloc);     // immediate : 0

  VERBOSE(1,("\n"));

  return ins_LDR_STR;
}

void Obfus_m_segv_4_revised::obfus_do_const_analysis(t_bbl* bbl, vector<pair<t_reg, t_uint32>>& vregConst)
{
  vregConst.clear();
  t_procstate* procstate = BBL_PROCSTATE_IN( bbl ); // analyse this bbl
  ASSERT(procstate != NULL, ("procstate is null; diabloanopt_constprop.c comment out the last foreach loop line #1537 - #1543."));
  t_register_content c;
  for (t_reg reg = ARM_REG_R0; reg <= ARM_REG_R15; reg++) {
    auto reg_level = ProcStateGetReg(procstate, reg, &c);
    if (reg_level != CP_BOT && reg_level != CP_TOP) {
      t_reloc *rel;
      auto tag_level = ProcStateGetTag(procstate, reg, &rel);
      if (tag_level != CP_BOT && tag_level != CP_TOP) { // dit register bevat een tag (=uitkomst van relocatie)
        //VERBOSE(0, ("\tanalysis<1> R%i tag := %02X", reg, AddressExtractUint32(c.i)));
      } else { // dit register bevat een constante
        //VERBOSE(0, ("\tanalysis<2> R%i := %02X", reg, AddressExtractUint32(c.i)));
        if (AddressExtractUint32(c.i) > 0)
          vregConst.push_back(make_pair(reg, AddressExtractUint32(c.i)));
      }
    }
  }
}

bool Obfus_m_segv_4_revised::obfus_process_stack_get_pairSplit_regB_check(std::pair<t_arm_ins*, s_bbl*>& pairSplit, s_ins* rsins)
{
  t_arm_ins* LDR_STR = rsins->ins;
  if (RegsetIn(ARM_INS_REGS_DEF(pairSplit.first), rsins->B)) {

    //if (ARM_INS_OPCODE(pairSplit.first) == ARM_ADD || ARM_INS_OPCODE(pairSplit.first) == ARM_SUB) {

    vector<pair<t_reg, t_uint32>> vregConst;
    obfus_do_const_analysis(pairSplit.second->bbl, vregConst);
    VERBOSE(1, ("vregConst size: %i", vregConst.size()));

    bool rB = false, rC = false;
    for (unsigned int i = 0; i < vregConst.size(); i++) {

      VERBOSE(1, ("\t vregConst[i] := %02X", vregConst[i].second));

      VERBOSE(1, ("\t r%i   =?  r%i",vregConst[i].first, ARM_INS_REGB(LDR_STR)));
      if (rB == false && vregConst[i].first == ARM_INS_REGB(LDR_STR))
        rB = true;

      VERBOSE(1, ("\t r%i   =?  r%i",vregConst[i].first, ARM_INS_REGC(LDR_STR)));
      if (rC == false && (vregConst[i].first == ARM_INS_REGC(LDR_STR) || ARM_REG_NONE == ARM_INS_REGC(LDR_STR)))
        rC = true; //could be immediate as well

    }
    if (rB == false || rC == false)
      return false;
    else
      return true;
  }
  // }

  /*
     not a single INS found which changes LDR_STR (using a simple instruction: ADD, SUB).
     actually; even if we found an INS that would change the LDR_STR's value
     and even if we could figure out the constant value in a register used by that INS,
     there will be NO guarantee that the constant value will be correct for that register
     because we eventually split the BBL in two or more parts, at a certain instruction,
     this also means that the instructions which generate the local constant value ("insensitive mode")
     will most likely not be executed, as they could appear in the other half of the split BBL.

     to make this method/strategy work requires too much bookkeeping and analysis,
     the chance of finding an ideal BBL will be very low.
     This failed for bzip2 with three protected regions.
     */

  return true;
}

void Obfus_m_segv_4_revised::postProcess()
{
  //// constant propagation analysis /////
  ASSERT(ConstantPropagationInit(data->cfg), ("constant propagation init failed"));
  ConstantPropagation (data->cfg, CONTEXT_SENSITIVE); // CONTEXT_SENSITIVE inter-BBL   CONTEXT_INSENSITIVE (only within BBL)
  OptUseConstantInformation(data->cfg, CONTEXT_SENSITIVE);
  //CfgRemoveDeadCodeAndDataBlocks (cfg);

  data->generate_instruction_maps();
  ASSERT(!data->ins_map_rw.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));

  VERBOSE(1, ("vm4:%i", vm4.size()));
  for (unsigned int i = 0; i < vm4.size(); i++) {
    sm4* sm = vm4[i];
    t_object* obj = sm->obj;
    t_regset available = RegsetNew();
    RegsetSetDup(available, sm->available);
    t_relocatable* target = sm->target;
    t_bbl* bbl = sm->obfus_final_bbl;


    ASSERT(!RegsetIsEmpty(available), ("Can not use this signalling encoding: At least 1 available register(s) required!"));

    vector<s_bbl*> vfil;
    data->intersect_available_and_mapped(available, data->ins_map_rw, vfil);
    ASSERT(!vfil.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));

    vector<pair<t_reg, t_uint32>> vregConst;
    vector<s_bbl*>::iterator it = vfil.begin();
    obfus_do_const_analysis(bbl, vregConst);
    VERBOSE(1, ("\t\t vregConst.size() := %i", vregConst.size()));
    VERBOSE(1, ("\t m4 vfil size: %i", vfil.size()));

    ASSERT(vregConst.size() > 0, ("Not a single reg with known cte found for current BBL 0x%02X", BBL_CADDRESS(bbl)));

    t_arm_ins* arm_ins;
    bool isThumb = ArmBblIsThumb(bbl);
    pair<s_bbl*, s_ins*> rpair;
    short int processi = 2;
    vector<t_arm_ins*> vfilINS;
    pair<t_arm_ins*, s_bbl*> pairSplit;
    while (processi != 0) {
      ASSERT(!vfil.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));
      rpair = obfus_get_random_struct(data->ins_map_rw, vfil, true);
      processi = obfus_process_rbbl(bbl, isThumb, rpair.first, rpair.second, vfilINS, pairSplit);
    }
    s_bbl* rbbl = rpair.first;
    s_ins* rsins = rpair.second;
    rbbl = obfus_perform_split(pairSplit, false).second;
    VERBOSE(1, ("\t jump to BBL @G",BBL_CADDRESS(rbbl->bbl)));

    //ArmMakeInsForBbl(Noop, Append, arm_ins, bbl, isThumb); // add Nop to make searching in asm easier !!! remove in production !!!
    // create dummy 'mov' which will be changed by AddressProducer into an ill_addr_encoded_offset.
    ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, rsins->B, ARM_REG_NONE, 0, ARM_CONDITION_AL);
    t_arm_ins* ill_ins_encoded = arm_ins; // the AddressProducer will use this instruction to store the ill_addr_encoded_offset.
    t_arm_ins* ins_LDR_STR = rsins->ins; // *from* this instruction, the offset will be calculated, to *to* migrated fragment.

    // add a jump instruction.
    ArmMakeInsForBbl(UncondBranch, Append, arm_ins, bbl, isThumb);
    // finally create edge matching the jump instruction is CFG.
    t_uint32 edge_jump_type = rbbl->bbl == bbl ? ET_JUMP : ET_IPJUMP;
    CfgEdgeCreate(data->cfg, bbl, rbbl->bbl, edge_jump_type);



    std::stringstream sstream, simmed;
    simmed  << "i" << std::hex << std::setw(8) << std::setfill('0') << rsins->immed;
    sstream << simmed.str() << "iFFFFFFFF" << "R00R01^^";
    if (rsins->neg_immed)
      sstream << "+";
    else
      sstream << "_";
    sstream << "\\" << WRITE_32;
    VERBOSE(1, (sstream.str().c_str()));

    t_reloc* reloc = RelocTableAddRelocToRelocatable(
        OBJECT_RELOC_TABLE(obj),
        AddressNullForObject(obj), // addend
        T_RELOCATABLE(ill_ins_encoded), // from   // address produced here
        AddressNullForObject(obj),  // from-offset
        target, // to  // R00 confirmed
        AddressNullForObject(obj), // to-offset
        FALSE, // hell
        NULL, // edge
        NULL, // corresp
        T_RELOCATABLE(ins_LDR_STR), // sec  //R01 confirmed
        sstream.str().c_str());
    ArmInsMakeAddressProducer(ill_ins_encoded, 0 , reloc);     // immediate : 0

    VERBOSE(1,("\n"));
  }

}

t_arm_ins* Obfus_m_segv_4_revised::encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target)
{
  sm4* s = new sm4();
  s->obj = obj;
  RegsetSetDup(s->available, available);
  s->obfus_final_bbl = bbl;
  s->target = target;
  vm4.push_back(s);

  return NULL;
}

void Obfus_m_segv_5::available_with_other_bbl(s_bbl* rbbl, s_ins* rsins, t_regset& available, t_regset& ret)
{
  t_reg tmpr;
  t_regset OLBBL = obfus_get_used_registers_current_state(rbbl->bbl); //live out registers in BBL of STR/LDR
  RegsetSetInvers(OLBBL);

  RegsetSetDup(ret, available); //copy available to ret
  if (RegsetIn(ret, rsins->B))
    RegsetSetSubReg(ret, rsins->B); // regB is an available register, but we may not use it for dead instructions; since it holds the ill_addr

  printLBBL(ret,   "cur avlbl: ");
  printLBBL(OLBBL, "oth avlbl: ");

  RegsetSetIntersect(ret, OLBBL); // intersect OLBBL with ret
  printLBBL(ret,   "=>  avlbl: ");

}

unsigned int Obfus_m_segv_5::insert_addr_ins(t_bbl* bbl, bool isThumb, t_regset& regs, t_reg& ill_reg)
{
  //ArmMakeInsForBbl(Noop, Append, arm_ins, bbl, isThumb); // add Nop to make searching in asm easier !!! remove in production !!!

  t_reg tmpr = ARM_REG_NONE;
  t_reg tmprr = ARM_REG_NONE;

  int m = 0;
  REGSET_FOREACH_REG(regs, tmpr)
    if (tmpr > m)
      m = tmpr; //find max reg value
  vector<unsigned int> vb(m+1, 0);

  REGSET_FOREACH_REG(regs, tmpr) {
    unsigned int d = 5;//1+rand()%10;
    vb[tmpr] = d;
    //ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, tmpr, ARM_REG_NONE, d, ARM_CONDITION_AL);
    tmprr = tmpr;
  }

  //REGSET_FOREACH_REG(regs, tmpr) {
  //  VERBOSE(0, ("vb[r%i] = vb[r%i]%i + vb[r%i]%i",tmpr,tmpr, vb[tmpr], tmprr, vb[tmprr]));
  //   vb[tmpr] = vb[tmpr] + vb[tmprr];
  //   ArmMakeInsForBbl(Add, Append, arm_ins, bbl, isThumb, tmpr, tmprr, tmpr, 0, ARM_CONDITION_AL);
  //  tmprr = tmpr;
  //}


  //ArmMakeInsForBbl(Sub, Append, arm_ins, bbl, isThumb, ill_reg, ill_reg, tmprr, 0, ARM_CONDITION_AL);


  //return vb[tmprr];
  //return 5;
  return 0;
}

t_arm_ins* Obfus_m_segv_5::encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target)
{
  //enforceDummyInstructions = false; // we set this to false since we will be adding custom instructions ; 'true' can be fatal and too restrictive for small applications.

  ASSERT(!data->ins_map_rw.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));
  ASSERT(!RegsetIsEmpty(available), ("Can not use this signalling encoding: At least 1 available register(s) required!"));

  vector<s_bbl*> vfil;
  data->intersect_available_and_mapped(available, data->ins_map_rw, vfil);
  ASSERT(!vfil.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));

  vector<t_arm_ins*> vfilINS;
  pair<t_arm_ins*, s_bbl*> pairSplit;
  pair<t_arm_ins*, s_bbl*> bestPairSplit;
  t_regset bestRegs = RegsetNew();

  bool findOptimalRegset = false; // if true, we will find the regset with most available registers (expensive operation!!!) ; otherwise first one with at least one available register.

  t_arm_ins* arm_ins;
  bool isThumb = ArmBblIsThumb(bbl);
  pair<s_bbl*, s_ins*> rpair;
  short int processi = 2;
  while (!vfil.empty()) {
    rpair = obfus_get_random_struct(data->ins_map_rw, vfil, true);
    processi = obfus_process_rbbl(bbl, isThumb, rpair.first, rpair.second, vfilINS, pairSplit);
    if (processi == 0) {
      // find available { register(s) \excl. rsins->B } intersected by available_regs( rbbl->bbl )
      t_regset vav = RegsetNew();
      available_with_other_bbl(rpair.first, rpair.second, available, vav);
      if (!RegsetIsEmpty(vav) && RegsetCountRegs(vav) > RegsetCountRegs(bestRegs)) {
        bestRegs = RegsetNew();
        RegsetSetDup(bestRegs, vav); //duplicate
        bestPairSplit = pairSplit; //store this bbl as potential candidate for split
        //VERBOSE(0, ("\t ici ret %i", RegsetCountRegs(bestRegs)));
        if (!findOptimalRegset)
          break; //alright, we found one
      }
      VERBOSE(1, ("------------"));
    }
  }
  s_bbl* rbbl = rpair.first;
  s_ins* rsins = rpair.second;
  VERBOSE(1, ("  ==========  "));
  // bestPairSplit not found ; re-building the program could help to have more luck
  ASSERT(bestPairSplit.first != NULL, ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));
  printLBBL(bestRegs, "final bestRegs: ");

  ////////
  //it's not allowed to re-use a INS::BBL with other anti_debugging regions, since both can have different program states, thus the inserted_neutral_ins can violate states.
  vector<s_bbl*>::iterator it = data->ins_map_rw.begin();
  t_arm_ins* sinsi = rsins->ins;
  while(it != data->ins_map_rw.end()) {

    vector<s_ins*>::iterator itj = (*it)->vsins->begin();
    while(itj != (*it)->vsins->end()) {
      if ((*itj)->ins == sinsi){
        itj = (*it)->vsins->erase(itj);
      } else {
        ++itj;
      }
    }

  }
  ///////////

  t_arm_ins* ins_LDR_STR = bestPairSplit.first; // *from* this instruction, the offset will be calculated, to *to* migrated fragment.

  pair<s_bbl*, s_bbl*> psp = obfus_perform_split(bestPairSplit, false); // split best candidate
  //VERBOSE(0, ("ici %i", BBL_NINS(psp.first->bbl)));
  if ( BBL_NINS(psp.first->bbl) > 0 ) {
    bestPairSplit.first  = T_ARM_INS(BBL_INS_FIRST(psp.second->bbl));
    bestPairSplit.second = psp.second;
    psp = obfus_perform_split(bestPairSplit, true);
  }
  rbbl = psp.first;

  VERBOSE(1, ("\t jump to BBL @G",BBL_CADDRESS(rbbl->bbl)));
  unsigned int addedValue = insert_addr_ins(rbbl->bbl, isThumb, bestRegs, rsins->B);


  // create dummy 'mov' which will be changed by AddressProducer into an ill_addr_encoded_offset.
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, rsins->B, ARM_REG_NONE, 0, ARM_CONDITION_AL);
  t_arm_ins* ill_ins_encoded = arm_ins; // the AddressProducer will use this instruction to store the ill_addr_encoded_offset.


  // add a jump instruction.
  ArmMakeInsForBbl(UncondBranch, Append, arm_ins, bbl, isThumb);
  // finally create edge matching the jump instruction is CFG.
  t_uint32 edge_jump_type = rbbl->bbl == bbl ? ET_JUMP : ET_IPJUMP;
  CfgEdgeCreate(data->cfg, bbl, rbbl->bbl, edge_jump_type);

  std::stringstream sstream, simmed, simmed2; //encode immed value into 32bit hex value (8 hex chars).
  simmed2 << "i" << std::hex << std::setw(8) << std::setfill('0') <<  (unsigned int)addedValue;
  simmed  << "i" << std::hex << std::setw(8) << std::setfill('0') <<  rsins->immed;
  sstream << simmed2.str() << simmed.str() << "iFFFFFFFF" << "R00R01^^";
  if (rsins->neg_immed)
    sstream << "+";
  else
    sstream << "_";
  sstream << "+" << "\\" << WRITE_32;

  VERBOSE(1, (sstream.str().c_str()));

  t_reloc* reloc = RelocTableAddRelocToRelocatable(
      OBJECT_RELOC_TABLE(obj),
      AddressNullForObject(obj), // addend
      T_RELOCATABLE(ill_ins_encoded), // from   // address produced here
      AddressNullForObject(obj),  // from-offset
      target, // to  // R00 confirmed
      AddressNullForObject(obj), // to-offset
      FALSE, // hell
      NULL, // edge
      NULL, // corresp
      T_RELOCATABLE(ins_LDR_STR), // sec  //R01 confirmed
      sstream.str().c_str());
  ArmInsMakeAddressProducer(ill_ins_encoded, 0 , reloc);     // immediate : 0

  VERBOSE(1,("\n"));

  return ins_LDR_STR;
}

unsigned int Obfus_m_segv_6::insert_addr_ins(t_bbl* bbl, bool isThumb, t_regset& regs, t_reg& ill_reg)
{
  t_arm_ins* arm_ins;
  //ArmMakeInsForBbl(Noop, Append, arm_ins, bbl, isThumb); // add Nop to make searching in asm easier !!! remove in production !!!
  t_reg tmpr = ARM_REG_NONE;
  t_reg tmprr = ARM_REG_NONE;

  VERBOSE(1, ("insert_addr_ins::"));
  REGSET_FOREACH_REG(regs, tmpr)
    VERBOSE(1, ("\t r%i", tmpr));

  // init array
  short int m = 0;
  REGSET_FOREACH_REG(regs, tmpr)
    if (tmpr > m)
      m = tmpr; //find max reg value
  vector<unsigned int> vb(m+1, 0);

  short int i = 0;
  REGSET_FOREACH_REG(regs, tmpr) {
    unsigned int d = RNGGenerateWithRange(data->rng, 0, 0xFFF);
    vb[tmpr] = d;
    ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, tmpr, ARM_REG_NONE, 0, ARM_CONDITION_AL);
    ArmMakeConstantProducer(arm_ins, d);
    tmprr = tmpr;
  }

  unsigned int tot = 0;
  REGSET_FOREACH_REG(regs, tmpr) {
    VERBOSE(1, ("vb[r%i] = vb[r%i]%i + vb[r%i]%i",tmpr,tmpr, vb[tmpr], tmprr, vb[tmprr]));
    vb[tmpr] = vb[tmpr] + vb[tmprr];
    tot = vb[tmpr];
    ArmMakeInsForBbl(Add, Append, arm_ins, bbl, isThumb, tmpr, tmprr, tmpr, 0, ARM_CONDITION_AL);
    tmprr = tmpr;
  }
  ArmMakeInsForBbl(Sub, Append, arm_ins, bbl, isThumb, ill_reg, ill_reg, tmprr, 0, ARM_CONDITION_AL);

  return tot;
}

t_arm_ins* Obfus_m_segv_6::encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target)
{
  //enforceDummyInstructions = true;

  ASSERT(!data->ins_map_rw.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));
  ASSERT((RegsetCountRegs(available) >= 2), ("Can not use this signalling encoding: At least 2 available register(s) required!"));

  vector<s_bbl*> vfil;
  data->intersect_available_and_mapped(available, data->ins_map_rw, vfil);
  ASSERT(!vfil.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));

  t_arm_ins* arm_ins;
  bool isThumb = ArmBblIsThumb(bbl);
  pair<s_bbl*, s_ins*> rpair;
  short int processi = 2;
  vector<t_arm_ins*> vfilINS;
  pair<t_arm_ins*, s_bbl*> pairSplit;
  t_regset rest;
  t_reg tmpr;
  while (processi != 0) {
    ASSERT(!vfil.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));
    rpair = obfus_get_random_struct(data->ins_map_rw, vfil, true);
    processi = obfus_process_rbbl(bbl, isThumb, rpair.first, rpair.second, vfilINS, pairSplit);

    if (processi == 0) {//let us test whether this solution is usable or not ::
      for (int i = 0; i < (int)vfilINS.size(); i++)
        VERBOSE(1, ("\t vfilINS: @G, type:%i, regA: %i, regB: %i, regC: %i, immed: %i",ARM_INS_CADDRESS(vfilINS[i]), ARM_INS_TYPE(vfilINS[i]), ARM_INS_REGA(vfilINS[i]), ARM_INS_REGB(vfilINS[i]), ARM_INS_REGC(vfilINS[i]), ARM_INS_IMMEDIATE(vfilINS[i])));

      // init rest :: contains all registers we may use for insert_addr_ins.
      rest = RegsetNew();
      REGSET_FOREACH_REG(available, tmpr)
        if (tmpr <= ARM_REG_R12)
          RegsetSetAddReg(rest, tmpr);
      RegsetSetSubReg(rest, rpair.second->B); // exclude the register holding ill_addr

      //lets use a random number of available registers (enhance randomness) ::
      short int N_rand_regs = RNGGenerateWithRange(data->rng, 1, RegsetCountRegs(rest));
      VERBOSE(1, ("We have %i available registers, but N_rand_regs := %i", RegsetCountRegs(rest), N_rand_regs));
      short int j = 0;
      REGSET_FOREACH_REG(rest, tmpr)
        if (++j > N_rand_regs)
          RegsetSetSubReg(rest, tmpr); // delete all the rest

      // processes the stack bottom-up ; find the new split position in BBL
      for (int i = vfilINS.size()-2; i >= 0; i--) { //omit last LDR/STR
        if (!RegsetIsEmpty(RegsetIntersect(ARM_INS_REGS_DEF(vfilINS[i]), rest))) { //find first instruction on stack, closest to STR/LDR which alters a register in 'rest'.
          vfilINS.erase(vfilINS.begin(), vfilINS.begin()+i);
          pairSplit.first = vfilINS[0];
          break;
        }
      }

      if (enforceDummyInstructions && vfilINS.size() == 1)
        processi = 2; //no good, try another solution.
    }
  }
  s_bbl* rbbl = rpair.first;
  s_ins* rsins = rpair.second;
  rbbl = obfus_perform_split(pairSplit, false).second;
  VERBOSE(1, ("\t jump to BBL @G",BBL_CADDRESS(rbbl->bbl)));


  // create dummy 'mov' which will be changed by AddressProducer into an ill_addr_encoded_offset.
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, rsins->B, ARM_REG_NONE, 0, ARM_CONDITION_AL);
  t_arm_ins* ill_ins_encoded = arm_ins; // the AddressProducer will use this instruction to store the ill_addr_encoded_offset.
  t_arm_ins* ins_LDR_STR = rsins->ins; // *from* this instruction, the offset will be calculated, to *to* migrated fragment.

  unsigned int addedValue = insert_addr_ins(bbl, isThumb, rest, rsins->B);

  // add a jump instruction.
  ArmMakeInsForBbl(UncondBranch, Append, arm_ins, bbl, isThumb);
  // finally create edge matching the jump instruction is CFG.
  t_uint32 edge_jump_type = rbbl->bbl == bbl ? ET_JUMP : ET_IPJUMP;
  CfgEdgeCreate(data->cfg, bbl, rbbl->bbl, edge_jump_type);


  std::stringstream sstream, sstreamops, simmed, simmed2; //encode immed value into 32bit hex value (8 hex chars).
  simmed2 << "i" << std::hex << std::setw(8) << std::setfill('0') <<  (unsigned int)addedValue;
  simmed  << "i" << std::hex << std::setw(8) << std::setfill('0') << rsins->immed;
  sstream << simmed2.str() << simmed.str() << "iFFFFFFFF" << "R00R01";
  sstreamops << "^^";
  if (rsins->neg_immed)
    sstreamops << "+";
  else
    sstreamops << "_";
  sstreamops << "+";
  sstream << sstreamops.str() << "\\" << WRITE_32;
  VERBOSE(1, ("%s", sstream.str().c_str()));



  t_reloc* reloc = RelocTableAddRelocToRelocatable(
      OBJECT_RELOC_TABLE(obj),
      AddressNullForObject(obj), // addend
      T_RELOCATABLE(ill_ins_encoded), // from   // address produced here
      AddressNullForObject(obj),  // from-offset
      target, // to  // R00 confirmed
      AddressNullForObject(obj), // to-offset
      FALSE, // hell
      NULL, // edge
      NULL, // corresp
      T_RELOCATABLE(ins_LDR_STR), // sec  //R01 confirmed
      sstream.str().c_str());
  ArmInsMakeAddressProducer(ill_ins_encoded, 0 , reloc);     // immediate : 0

  VERBOSE(1,("\n"));

  return ins_LDR_STR;
}

void Obfus_m_segv_7::insert_ctx_code(t_bbl* from_bbl, s_bbl* rbbl, s_ins* rsins, t_arm_condition_code cond, t_relocatable* target, t_regset& rest, bool isThumb, t_object* obj)
{
  //lets use a random number of available registers (enhance randomness) ::
  t_regset rest_A = RegsetNew();
  RegsetSetDup(rest_A, rest);
  short int N_rand_regs = RNGGenerateWithRange(data->rng, 1, RegsetCountRegs(rest_A));
  VERBOSE(1, ("We have %i available registers, but N_rand_regs := %i", RegsetCountRegs(rest_A), N_rand_regs));
  short int j = 0;
  t_reg tmpr;
  REGSET_FOREACH_REG(rest_A, tmpr)
    if (++j > N_rand_regs)
      RegsetSetSubReg(rest_A, tmpr); // delete all the rest

  t_arm_ins* arm_ins;
  //ArmMakeInsForBbl(Noop, Append, arm_ins, from_bbl, isThumb);
  // create dummy 'mov' which will be changed by AddressProducer into an ill_addr_encoded_offset.
  ArmMakeInsForBbl(Mov, Append, arm_ins, from_bbl, isThumb, rsins->B, ARM_REG_NONE, 0, ARM_CONDITION_AL);
  t_arm_ins* ill_ins_encoded_A = arm_ins; // the AddressProducer will use this instruction to store the ill_addr_encoded_offset.
  t_arm_ins* ins_LDR_STR = rsins->ins; // *from* this instruction, the offset will be calculated, to *to* migrated fragment.

  unsigned int addedValue = insert_addr_ins(from_bbl, isThumb, rest_A, rsins->B);
  VERBOSE(1, ("addedValue: %02x", addedValue));

  if (cond == ARM_CONDITION_AL)
    ArmMakeInsForBbl(UncondBranch, Append, arm_ins, from_bbl, isThumb); // add a jump instruction.
  else
    ArmMakeInsForBbl(CondBranch, Append, arm_ins, from_bbl, isThumb, cond); // add a jump instruction.

  t_uint32 edge_jump_type = rbbl->bbl == from_bbl ? ET_JUMP : ET_IPJUMP;
  VERBOSE(1, ("Edge from @G to @G.", BBL_CADDRESS(from_bbl), BBL_CADDRESS(rbbl->bbl)));
  CfgEdgeCreate(data->cfg, from_bbl, rbbl->bbl, edge_jump_type); // finally create edge matching the jump instruction is CFG.

  std::stringstream sstream, sstreamops, simmed, simmed2; //encode immed value into 32bit hex value (8 hex chars).
  simmed2 << "i" << std::hex << std::setw(8) << std::setfill('0') <<  (unsigned int)addedValue;
  simmed  << "i" << std::hex << std::setw(8) << std::setfill('0') << rsins->immed;
  sstream << simmed2.str() << simmed.str() << "iFFFFFFFF" << "R00R01";
  sstreamops << "^^";
  if (rsins->neg_immed)
    sstreamops << "+";
  else
    sstreamops << "_";
  sstreamops << "+";
  sstream << sstreamops.str() << "\\" << WRITE_32;
  VERBOSE(1, ("%s", sstream.str().c_str()));

  t_reloc* reloc = RelocTableAddRelocToRelocatable(
      OBJECT_RELOC_TABLE(obj),
      AddressNullForObject(obj), // addend
      T_RELOCATABLE(ill_ins_encoded_A), // from   // address produced here
      AddressNullForObject(obj),  // from-offset
      target, // to  // R00 confirmed
      AddressNullForObject(obj), // to-offset
      FALSE, // hell
      NULL, // edge
      NULL, // corresp
      T_RELOCATABLE(ins_LDR_STR), // sec  //R01 confirmed
      sstream.str().c_str());
  ArmInsMakeAddressProducer(ill_ins_encoded_A, 0 , reloc);     // immediate : 0
}

t_arm_condition_code Obfus_m_segv_7::random_cond()
{
  short int j = 0;
  short int R = RNGGenerateWithRange(data->rng, 0, 16);
  switch (R) {
    case 0:
      return ARM_CONDITION_VS;
    case 1:
      return ARM_CONDITION_CC;
    case 2:
      return ARM_CONDITION_CS;
    case 3:
      return ARM_CONDITION_EQ;
    case 4:
      return ARM_CONDITION_GE;
    case 5:
      return ARM_CONDITION_GT;
    case 6:
      return ARM_CONDITION_HI;
    case 7:
      return ARM_CONDITION_HS;
    case 8:
      return ARM_CONDITION_LE;
    case 9:
      return ARM_CONDITION_LO;
    case 10:
      return ARM_CONDITION_LS;
    case 11:
      return ARM_CONDITION_LT;
    case 12:
      return ARM_CONDITION_MI;
    case 13:
      return ARM_CONDITION_NE;
    case 14:
      return ARM_CONDITION_NV;
    case 15:
      return ARM_CONDITION_PL;
    default:
      return ARM_CONDITION_VC;
  }
}

t_arm_ins* Obfus_m_segv_7::encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target)
{
  //enforceDummyInstructions = true;

  ASSERT(!data->ins_map_rw.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));
  ASSERT((RegsetCountRegs(available) >= 2), ("Can not use this signalling encoding: At least 2 available register(s) required!"));

  vector<s_bbl*> vfil;
  data->intersect_available_and_mapped(available, data->ins_map_rw, vfil);
  ASSERT(!vfil.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));

  t_arm_ins* arm_ins;
  bool isThumb = ArmBblIsThumb(bbl);
  pair<s_bbl*, s_ins*> rpair;
  short int processi = 2;
  vector<t_arm_ins*> vfilINS;
  pair<t_arm_ins*, s_bbl*> pairSplit;
  t_regset rest;
  t_reg tmpr;
  while (processi != 0) {
    ASSERT(!vfil.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));
    rpair = obfus_get_random_struct(data->ins_map_rw, vfil, true);
    processi = obfus_process_rbbl(bbl, isThumb, rpair.first, rpair.second, vfilINS, pairSplit);

    if (processi == 0) {//let us test whether this solution is usable or not ::
      for (int i = 0; i < (int)vfilINS.size(); i++)
        VERBOSE(1, ("\t vfilINS: @G, type:%i, regA: %i, regB: %i, regC: %i, immed: %i",ARM_INS_CADDRESS(vfilINS[i]), ARM_INS_TYPE(vfilINS[i]), ARM_INS_REGA(vfilINS[i]), ARM_INS_REGB(vfilINS[i]), ARM_INS_REGC(vfilINS[i]), ARM_INS_IMMEDIATE(vfilINS[i])));

      // init rest :: contains all registers we may use for insert_addr_ins.
      rest = RegsetNew();
      REGSET_FOREACH_REG(available, tmpr)
        if (tmpr <= ARM_REG_R12)
          RegsetSetAddReg(rest, tmpr);
      RegsetSetSubReg(rest, rpair.second->B); // exclude the register holding ill_addr

      // processes the stack bottom-up ; find the new split position in BBL
      for (int i = vfilINS.size()-2; i >= 0; i--) { //omit last LDR/STR
        if (!RegsetIsEmpty(RegsetIntersect(ARM_INS_REGS_DEF(vfilINS[i]), rest))) { //find first instruction on stack, closest to STR/LDR which alters a register in 'rest'.
          vfilINS.erase(vfilINS.begin(), vfilINS.begin()+i);
          pairSplit.first = vfilINS[0];
          break;
        }
      }

      if (enforceDummyInstructions && vfilINS.size() == 1)
        processi = 2; //no good, try another solution.
    }
  }
  s_bbl* rbbl = rpair.first;
  s_ins* rsins = rpair.second;
  rbbl = obfus_perform_split(pairSplit, false).second;
  VERBOSE(1, ("\t jump to BBL @G",BBL_CADDRESS(rbbl->bbl)));


  t_arm_condition_code rcond = random_cond(); // one may also use the proposed strategy as in segv_8 ; instead of picking a random condition for branch.

  // if splitting ever fails, use: "BblSplitBlockNoTestOnBranches" instead of "BblSplitBlock"
  t_bbl* bbl_A = BblSplitBlock(bbl, T_INS(BBL_INS_LAST(bbl)), FALSE /* before */); // brand new/empty BBL **fallthrough edge created automatically
  insert_ctx_code(bbl_A, rbbl, rsins, ARM_CONDITION_AL, target, rest, isThumb, obj);
  insert_ctx_code(bbl, rbbl, rsins, rcond, target, rest, isThumb, obj);
  VERBOSE(1,("\n"));

  return rsins->ins;
}

void Obfus_m_segv_8::find_rbbl(s_bbl*& rbbl, s_ins*& rsins, t_regset& rest, t_bbl* bbl, bool isThumb, t_regset& available, vector<s_bbl*>& vfil)
{
  short int processi = 2;
  vector<t_arm_ins*> vfilINS;
  pair<t_arm_ins*, s_bbl*> pairSplit;
  t_reg tmpr;
  pair<s_bbl*, s_ins*> rpair;
  while (processi != 0) {
    ASSERT(!vfil.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));
    rpair = obfus_get_random_struct(data->ins_map_rw, vfil, true);
    processi = obfus_process_rbbl(bbl, isThumb, rpair.first, rpair.second, vfilINS, pairSplit);
    if (processi == 0) {//let us test whether this solution is usable or not ::
      for (int i = 0; i < (int)vfilINS.size(); i++)
        VERBOSE(1, ("\t vfilINS: @G, type:%i, regA: %i, regB: %i, regC: %i, immed: %i",ARM_INS_CADDRESS(vfilINS[i]), ARM_INS_TYPE(vfilINS[i]), ARM_INS_REGA(vfilINS[i]), ARM_INS_REGB(vfilINS[i]), ARM_INS_REGC(vfilINS[i]), ARM_INS_IMMEDIATE(vfilINS[i])));
      // init rest :: contains all registers we may use for insert_addr_ins.
      rest = RegsetNew();
      REGSET_FOREACH_REG(available, tmpr)
        if (tmpr <= ARM_REG_R12)
          RegsetSetAddReg(rest, tmpr);
      RegsetSetSubReg(rest, rpair.second->B); // exclude the register holding ill_addr
      // processes the stack bottom-up ; find the new split position in BBL
      for (int i = vfilINS.size()-2; i >= 0; i--) { //omit last LDR/STR
        if (!RegsetIsEmpty(RegsetIntersect(ARM_INS_REGS_DEF(vfilINS[i]), rest))) { //find first instruction on stack, closest to STR/LDR which alters a register in 'rest'.
          vfilINS.erase(vfilINS.begin(), vfilINS.begin()+i);
          pairSplit.first = vfilINS[0];
          break;
        }
      }
      if (enforceDummyInstructions && vfilINS.size() == 1)
        processi = 2; //no good, try another solution.
    }
  }
  rsins = rpair.second;
  rbbl = obfus_perform_split(pairSplit, false).second;
  VERBOSE(1, ("current BBL: @G", BBL_CADDRESS(bbl)));
  VERBOSE(1, ("\t jump to BBL @G",BBL_CADDRESS(rbbl->bbl)));
}

t_arm_condition_code Obfus_m_segv_8::determine_condition_based_on_flag(t_bbl* bbl)
{
  // find one or more live flags
  t_regset flags = RegsetNew();
  RegsetSetAddReg(flags, ARM_REG_C_CONDITION);
  RegsetSetAddReg(flags, ARM_REG_V_CONDITION);
  RegsetSetAddReg(flags, ARM_REG_Z_CONDITION);
  RegsetSetAddReg(flags, ARM_REG_N_CONDITION);

  t_regset live = RegsetNew();
  RegsetSetDup(live, BblRegsLiveAfter(bbl));

  t_regset liveFlags = RegsetIntersect(live, flags);
  short int N = RegsetCountRegs(liveFlags);
  t_reg tmpr;
  VERBOSE(1, ("liveFlags %i", N));
  if (N > 0) {
    //let us choose a random condition based on a live flag
    short int R = RNGGenerateWithRange(data->rng, 0, N-1);
    short int i = 0;
    REGSET_FOREACH_REG(liveFlags, tmpr) {
      VERBOSE(1, ("r%i", tmpr));
      if (i++ == R)
        break;
    }
    bool b = RNGGenerateBool(data->rng);
    switch(tmpr) {
      case ARM_REG_C_CONDITION:
        if (b) return ARM_CONDITION_CS;
        else return ARM_CONDITION_CC;
      case ARM_REG_V_CONDITION:
        if (b) return ARM_CONDITION_VS;
        else return ARM_CONDITION_VC;
      case ARM_REG_Z_CONDITION:
        if (b) return ARM_CONDITION_EQ;
        else return ARM_CONDITION_NE;
      case ARM_REG_N_CONDITION:
        return ARM_CONDITION_MI;
    }
  }
  return ARM_CONDITION_AL; // all flags are dead
}

t_arm_ins* Obfus_m_segv_8::encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target)
{
  //enforceDummyInstructions = true;
  delete_INS_BBL_FromMapping = false; //for small applications it may not find enough distinct instructions to branch to.

  ASSERT(!data->ins_map_rw.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));
  ASSERT((RegsetCountRegs(available) >= 2), ("Can not use this signalling encoding: At least 2 available register(s) required!"));

  vector<s_bbl*> vfil;
  data->intersect_available_and_mapped(available, data->ins_map_rw, vfil);
  ASSERT(!vfil.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));

  t_arm_ins* arm_ins;
  bool isThumb = ArmBblIsThumb(bbl);
  t_regset restA, restB;
  s_bbl* rbblA = NULL;
  s_ins* rsinsA = NULL;
  s_bbl* rbblB = NULL;
  s_ins* rsinsB = NULL;
  find_rbbl(rbblA, rsinsA, restA, bbl, isThumb, available, vfil);
  find_rbbl(rbblB, rsinsB, restB, bbl, isThumb, available, vfil);

  // instead of just choosing a random condition; let us try to use a condition based on any live flags.
  t_arm_condition_code rcond = determine_condition_based_on_flag(bbl);
  if (rcond == ARM_CONDITION_AL) { // not a single live flag found; all are dead
    // find two live regs, add CMP since we are allowed to use/alter the flags now.
    t_regset live = BblRegsLiveAfter(bbl);
    t_reg rxA = ARM_REG_R0;
    t_reg rxB = ARM_REG_R1;
    REGSET_FOREACH_REG(live, rxA) {
      RegsetSetSubReg(live, rxA);
      break;
    }
    REGSET_FOREACH_REG(live, rxB) {
      RegsetSetSubReg(live, rxB);
      break;
    }
    ArmMakeInsForBbl(Cmp, Append, arm_ins, bbl, isThumb, rxA, rxB, 0, ARM_CONDITION_AL);
    rcond = RNGGenerateBool(data->rng) ? ARM_CONDITION_LE : ARM_CONDITION_GT ;
  }

  ArmMakeInsForBbl(Noop, Append, arm_ins, bbl, isThumb); // add Nop to make searching in asm easier !!! remove in production !!!

  //split first (otherwise CFG edge gets messed up)
  t_bbl* bbl_A = BblSplitBlockNoTestOnBranches(bbl, T_INS(BBL_INS_LAST(bbl)), FALSE /* before */); // brand new/empty BBL **fallthrough edge created automatically
  //notice that we use 'BblSplitBlockNoTestOnBranches' --> otherwise weird problem when trying to split (wrong out-edge type == 2048) -.-#
  //t_bbl* bbl_A = BblSplitBlock(bbl, T_INS(BBL_INS_LAST(bbl)), FALSE /* before */); // brand new/empty BBL **fallthrough edge created automatically

  //add cond branch
  insert_ctx_code(bbl, rbblB, rsinsB, rcond, target, restB, isThumb, obj);
  //add branch
  insert_ctx_code(bbl_A, rbblA, rsinsA, ARM_CONDITION_AL, target, restA, isThumb, obj);

  return NULL;
}

t_arm_ins* Obfus_m_segv_9::encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target)
{
  ASSERT(!data->ins_map_rw.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));
  ASSERT(!RegsetIsEmpty(available), ("Can not use this signalling encoding: At least 1 available register(s) required!"));

  // look for an available register: regB which will hold the ill_addr_encoded_offset.
  t_reg regB = ARM_REG_NONE;
  REGSET_FOREACH_REG(available, regB)
    if (regB <= ARM_REG_R12)
      break;

  // when not a single register is available; and we shouldn't push, since we cannot know if we'll have to pop in debugger.
  ASSERT(!(regB == ARM_REG_NONE || regB > ARM_REG_R12), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));

  t_arm_ins* arm_ins;
  bool isThumb = ArmBblIsThumb(bbl);
  //ArmMakeInsForBbl(Noop, Append, arm_ins, bbl, isThumb); // add Nop to make searching in asm easier !!! remove in production !!!
  // create dummy 'mov' which will be changed by AddressProducer into an ill_addr_encoded_offset.
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, regB, ARM_REG_NONE, 0, ARM_CONDITION_AL);
  t_arm_ins* ill_ins_encoded = arm_ins; // the AddressProducer will use this instruction to store the ill_addr_encoded_offset.


  ArmMakeInsForBbl(Push, Append, arm_ins, bbl, isThumb, 1 << ARM_REG_R14, ARM_CONDITION_AL, isThumb);

  // add BX instruction
  ArmMakeInsForBbl(UncondBranch, Append, arm_ins, bbl, isThumb);
  ARM_INS_SET_OPCODE(arm_ins, ARM_BX);
  ARM_INS_SET_REGA(arm_ins, ARM_REG_NONE);
  ARM_INS_SET_REGB(arm_ins, regB);
  ARM_INS_SET_REGC(arm_ins, ARM_REG_NONE);
  /*
     Inserting a BLX instruction causes problems;
     for some reason Diablo is unable to properly add a BLX
     the inserted instruction is a BLX with a label (PC relative address) instead our register (regB).
     */

  std::stringstream sstream, sstreamops; //encode immed value into 32bit hex value (8 hex chars).
  sstream << "iC0000000" << "R00";
  sstreamops << "+";
  sstream << sstreamops.str() << "\\" << WRITE_32;
  VERBOSE(1, ("%s", sstream.str().c_str()));

  /*  we use 0xC0000000 instead of 0xFFFFFFFF
      simply because eg: 0xFFFFFFFF - 0x800C = 0xFFFF7FF3
      when the branch happens, the kernel/CPU will correct it
      and the PC register is changed to 0xFFFF7FF2 (using a heuristic for alignment)
      but if we add to 0xC0000000 we don't have this problem.
      */


  t_reloc* reloc = RelocTableAddRelocToRelocatable(
      OBJECT_RELOC_TABLE(obj),
      AddressNullForObject(obj), /* addend */
      T_RELOCATABLE(ill_ins_encoded), /* from */  // address produced here
      AddressNullForObject(obj),  /* from-offset */
      target, /* to */ // R00 confirmed
      AddressNullForObject(obj), /* to-offset */
      FALSE, /* hell */
      NULL, /* edge*/
      NULL, /* corresp */
      NULL, /* sec */ //R01 confirmed
      sstream.str().c_str());
  ArmInsMakeAddressProducer(ill_ins_encoded, 0 /* immediate */, reloc);

  return arm_ins;
}

t_arm_ins* Obfus_m_segv_10::encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target)
{
  delete_INS_BBL_FromMapping = false; //for small applications it may not find enough distinct instructions to branch to.

  ASSERT(!data->ins_map_x.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));

  RegsetSetAddReg(available, ARM_REG_R14);// We may use the LR register because we PUSH it onto stack!!! (**)

  vector<s_bbl*> vfil;
  data->intersect_available_and_mapped(available, data->ins_map_x, vfil);
  ASSERT(!vfil.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));

  t_arm_ins* arm_ins;
  bool isThumb = ArmBblIsThumb(bbl);
  pair<s_bbl*, s_ins*> rpair;
  short int processi = 2;
  vector<t_arm_ins*> vfilINS;
  pair<t_arm_ins*, s_bbl*> pairSplit;
  while (processi != 0) {
    ASSERT(!vfil.empty(), ("The chosen OBFUS_METHOD has failed due to some reason. Try building it again?"));
    rpair = obfus_get_random_struct(data->ins_map_x, vfil, true);
    processi = obfus_process_rbbl(bbl, isThumb, rpair.first, rpair.second, vfilINS, pairSplit);
  }
  s_bbl* rbbl = rpair.first;
  s_ins* rsins = rpair.second;
  rbbl = obfus_perform_split(pairSplit, false).second;
  VERBOSE(1, ("\t jump to BBL @G",BBL_CADDRESS(rbbl->bbl)));

  /* push/preserve LR register, since a BLX can disrupt its value ; debugger will restore it using stack */
  ArmMakeInsForBbl(Push, Append, arm_ins, bbl, isThumb, 1 << ARM_REG_R14, ARM_CONDITION_AL, isThumb);

  // create dummy 'mov' which will be changed by AddressProducer into an ill_addr_encoded_offset.
  ArmMakeInsForBbl(Mov, Append, arm_ins, bbl, isThumb, rsins->B, ARM_REG_NONE, 0, ARM_CONDITION_AL);
  t_arm_ins* ill_ins_encoded = arm_ins; // the AddressProducer will use this instruction to store the ill_addr_encoded_offset.
  t_arm_ins* ins_BRANCH = rsins->ins; // *from* this instruction, the offset will be calculated, to *to* migrated fragment.


  // add a jump instruction.
  ArmMakeInsForBbl(UncondBranch, Append, arm_ins, bbl, isThumb);
  // finally create edge matching the jump instruction is CFG.
  t_uint32 edge_jump_type = rbbl->bbl == bbl ? ET_JUMP : ET_IPJUMP;
  CfgEdgeCreate(data->cfg, bbl, rbbl->bbl, edge_jump_type);


  std::stringstream sstream, sstreamops; //encode immed value into 32bit hex value (8 hex chars).
  sstream << "iC0000000" << "R00";
  sstreamops << "+";
  sstream << sstreamops.str() << "\\" << WRITE_32;
  VERBOSE(1, ("%s", sstream.str().c_str()));
  /*  we use 0xC0000000 instead of 0xFFFFFFFF
      simply because eg: s0xFFFFFFFF - 0x800C = 0xFFFF7FF3
      when the branch happens, the kernel/CPU will correct it
      and the PC register is changed to 0xFFFF7FF2 (using a heuristic for alignment)
      but if we add to 0xC0000000 we don't have this problem.
      */


  t_reloc* reloc = RelocTableAddRelocToRelocatable(
      OBJECT_RELOC_TABLE(obj),
      AddressNullForObject(obj), /* addend */
      T_RELOCATABLE(ill_ins_encoded), /* from */  // address produced here
      AddressNullForObject(obj),  /* from-offset */
      target, /* to */ // R00 confirmed
      AddressNullForObject(obj), /* to-offset */
      FALSE, /* hell */
      NULL, /* edge*/
      NULL, /* corresp */
      NULL, /* sec */ //R01 confirmed
      sstream.str().c_str());
  ArmInsMakeAddressProducer(ill_ins_encoded, 0 /* immediate */, reloc);

  return ins_BRANCH;
}
