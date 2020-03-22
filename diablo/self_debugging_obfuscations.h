/* AUTHORS:
 * Bert Abrath
 * Ilja Nevolin
 */

#ifndef _SELFDEBUGGING_OBFUSCATIONS_H_
#define _SELFDEBUGGING_OBFUSCATIONS_H_

#include <memory>
#include <stack>
#include <string>
#include <vector>

extern "C" {
#include <diablosupport.h>
#include <diabloanopt.h>
#include <diabloanoptarm.h>
#include <diabloarm.h>
#include <diabloflowgraph.h>
}

class s_ins {
  public:
    t_arm_ins* ins=0;     // LDR/STR instruction
    _t_arm_opcode opc;    // ARM_STR or AMR_LDR
    t_reg A, B, C;
    t_uint32 immed;
    bool neg_immed; //if immediate is negative value (subtracting offset) ;

    s_ins(t_arm_ins* arm_ins);
};

struct s_bbl {
  std::vector<s_ins*>* vsins;
  t_bbl* bbl;
  s_bbl* next=0;
};

class ObfusData {
  public:
  /*
    IS_MUTILATED_ADDR_MAPPING ::
      Lets use a simple strategy to verify whether a context switch (signal invocation) is intended to execute/process a migrated fragement
      or maybe it was a random/natural occurrence.
      If this variable is set to "true" then the addr_mapping will be mutilated, so we shall only have an addr_mapping of partially correct offsets.
      These partiall correct offsets can be used to match/validate  a computed dest address at runtime.
  */
    static const bool IS_MUTILATED_ADDR_MAPPING = true;
    static const unsigned int MUTILATION_MASK_ADR_MAP = 0xF0F0F0F0;
    //if 'IS_MUTILATED_ADDR_MAPPING' is enabled ==> the address mapping will be mutilated for those methods who rely on it.
    t_randomnumbergenerator *rng;
    std::vector<s_bbl*> ins_map_rw;
    std::vector<s_bbl*> ins_map_x;
    t_cfg* cfg;
    t_section* fault_map_sec;
    t_uint32 fault_map_entry_size;/* The size of one entry */
    std::vector<t_arm_ins*> faulting_instructions;

    static void obfuscate_mapping(t_object* obj, t_reloc* reloc);
    static bool is_legal_branch(t_bbl* bbl, t_arm_ins* arm_ins);
    static bool is_legal_loadstore(t_bbl* bbl, t_arm_ins* arm_ins);

    void delete_from_ins_map(std::vector<s_bbl*>& ins_map, s_bbl* sbbl, s_ins* sins);
    std::vector<s_bbl*> intersect_available_and_mapped(t_regset& available, std::vector<s_bbl*>& ins_map);
    void generate_instruction_maps();
    void FaultMapAddEntry(t_object* obj, t_arm_ins* fault_ins, const t_reloc* reloc);
    ObfusData(t_cfg* cfg, t_symbol* fault_map_sym);
};

// abstract class:
class Obfus {
  protected:
    ObfusData* data;

  public:
    Obfus(ObfusData* data) : data(data) {}
    virtual ~Obfus() {}
    static void choose_method(std::unique_ptr<Obfus>& obfus, const t_regset available, t_bool incoming_edge, ObfusData* data);
    virtual void encode_constant(t_object* obj, t_bbl* bbl, t_regset& available, t_uint32 adr_size, t_uint32 constant);
    virtual void encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target) = 0;
};

// concrete implementations:
class Obfus_m_bkpt_1 			: public Obfus {
  // original BKPT method
  public:
    Obfus_m_bkpt_1(ObfusData* data) : Obfus(data) {};
    virtual void encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target);
};

// SIGFPE and SIGILL methods:
class Obfus_m_fpe_1 			: public Obfus {
  // division by zero using the stack+mapping
  // notice: In the ARMv7-R profile, the implementation of SDIV and UDIV in the ARM instruction set is OPTIONAL.
  // on our ARMv7 board this method generates a SIGILL (illegal instruction signal)  instead of a SEGFPE, but it works.
  // It is highly advised to use this method for experimental/educational purposes only.
  public:
    Obfus_m_fpe_1(ObfusData* data) : Obfus(data) {};
    virtual void encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target);
};

class Obfus_m_fpe_2 			: public Obfus {
  // division by zero and storing offset [PC, dest] in numerator.
  // notice: In the ARMv7-R profile, the implementation of SDIV and UDIV in the ARM instruction set is OPTIONAL.
  // on our ARMv7 board this method generates a SIGILL (illegal instruction signal)  instead of a SEGFPE, but it works.
  // It is highly advised to use this method for experimental/educational purposes only.
  public:
    Obfus_m_fpe_2(ObfusData* data) : Obfus(data) {};
    virtual void encode_constant(t_object* obj, t_bbl* bbl, t_regset& available, t_uint32 adr_size, t_uint32 constant) {}
    virtual void encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target);
};

// SIGSEGV methods:
class Obfus_segv_abstract 		: public Obfus {
  protected:
    bool enforceDummyInstructions = true;     // may get stuck in infin. loop + segmentation fault      !!! in product set to false !!!
    bool onlySimpleDummyInstructions = false; // may get stuck in infin. loop + segmentation fault      !!! in product set to false !!!

    virtual bool obfus_is_legal_INS_LOAD_STORE_MANY(t_bbl* bbl, t_arm_ins* arm_ins);

  public:
    //initialization list
    Obfus_segv_abstract(ObfusData* data, bool enforceDummyInstructions) : Obfus(data), enforceDummyInstructions(enforceDummyInstructions) {}
};

class Obfus_m_segv_1 			: public Obfus_segv_abstract {
  // use random_ill_addr and jmp to random STR/LDR and using the stack+mapping

  protected:
    bool delete_INS_BBL_FromMapping = true; // if true: disallow usage of same LDR/STR instruction for different context switches.
    t_uint32 obfus_generate_random_ill_addr(t_uint32 immed, bool neg_immed);
    void obfus_add_illegal_address(t_bbl* bbl, bool isThumb, t_reg regB, t_uint32 immed, bool neg_immed);
    virtual void obfus_fill_stack_from_bbl(s_bbl* rbbl, s_ins* rsins, std::stack< std::pair<t_arm_ins*, s_bbl*> >& st);
    virtual bool obfus_process_stack_get_pairSplit_regB_check(std::pair<t_arm_ins*, s_bbl*>& pairSplit, s_ins* rsins);
    virtual std::pair<t_arm_ins*, s_bbl*> obfus_process_stack_get_pairSplit(t_bbl* bbl, s_ins* rsins, t_regset& LBBL, std::stack< std::pair<t_arm_ins*, s_bbl*> >& st, std::vector<t_arm_ins*>& vfilINS);
    std::pair<s_bbl*, s_bbl*> obfus_perform_split(std::pair<t_arm_ins*, s_bbl*>& pairSplit, bool force);
    virtual std::pair<int, s_bbl*> obfus_prepare_rbbl(s_bbl* rbbl, s_ins* rsins, t_bbl* bbl, std::vector<t_arm_ins*>& vfilINS, std::pair<t_arm_ins*, s_bbl*>& pairSplit);
    std::pair<s_bbl*, s_ins*> obfus_get_random_struct(std::vector<s_bbl*>& ins_map,std::vector<s_bbl*>& vfil, bool deleteFromVFIL);
    short int obfus_process_rbbl(t_bbl* bbl, bool isThumb, s_bbl*& rbbl, s_ins* rsins, std::vector<t_arm_ins*>& vfilINS, std::pair<t_arm_ins*, s_bbl*>& pairSplit);

  public:
    Obfus_m_segv_1(ObfusData* data, bool enforceDummyInstructions) : Obfus_segv_abstract(data, enforceDummyInstructions) {}
    virtual void encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target);
};

class Obfus_m_segv_2 			: public Obfus_m_segv_1 {
  // generate ill_addr_encoded_offset and jmp to random STR/LDR
  public:
    Obfus_m_segv_2(ObfusData* data, bool enforceDummyInstructions) : Obfus_m_segv_1(data, enforceDummyInstructions) {}
    virtual void encode_constant(t_object* obj, t_bbl* bbl, t_regset& available, t_uint32 adr_size, t_uint32 constant) {}
    virtual void encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target);
};

class Obfus_m_segv_3 			: public Obfus_m_segv_2 {
  // simplified version of m_2: insert a random STR/LDR instead of jumping to existing one.
  public:
    Obfus_m_segv_3(ObfusData* data) : Obfus_m_segv_2(data, false) {}
    virtual void encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target);
};

// DEPRECATED ::
class Obfus_m_segv_4 			: public Obfus_m_segv_2 {
  // incomplete & deprecated !!! do not use !!!
  // advanced version of m_2: starting value is re-constructed on-the-go into a valid ill_addr_encoded_offset, by certain instructions in the BBL where we jump to
  /*
    Method explained:
      In the first phase the CFG is analysed and if any constant value of a register determined.
      In the second phase we create/split some BBLs to make a context switch possible :: final_bbl.
        Then we go out to find all BBLs that has a LDR/STR instruction where the 'from' register is available and we can fill it with an ill_addr.
        Once we have this list of BBLs, we remove all those BBLs from the list that do not have a known constant value for a certain register.
        Finally, we choose a random BBL from this final list and find the first possible instruction we can jump to;
          in such a way that all consecutive instructions, up to the LDR/STR, do not alter the current program's state.

    Problem with this method:
      This method doesn't work simply because the constant values we've found are constant during normal program execution (from __start to the BBL).
      But it is NOT GUARANTEED that, say R7 which has a CTE value of 0x15 will still have that value once we jump to a random position in that BBL where R7 has that value under normal execution.
      We jump to a random BBL from 'final_bbl', but in 'final_bbl', R7 can have any other value.
      To fix this problem, kindly see Obfus_m_segv_4_revised.
  */
  protected:
    void obfus_do_const_analysis(t_bbl* bbl, std::vector<std::pair<t_reg, t_uint32>>& vregConst);
    virtual bool obfus_process_stack_get_pairSplit_regB_check(std::pair<t_arm_ins*, s_bbl*>& pairSplit, s_ins* rsins);

  public:
    Obfus_m_segv_4(ObfusData* data, bool enforceDummyInstructions) : Obfus_m_segv_2(data, enforceDummyInstructions) { FATAL(("DEPRECATED")); }
    virtual void encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target);
};

// DEPRECATED ::
class Obfus_m_segv_4_revised 	: public Obfus_m_segv_4 {
  // incomplete & deprecated !!! do not use !!!
  /*
    Method explained:
      Works quite similar as the normal segv_4 method.
      Except that the CFG analysis is carried out after we've created/split any BBLs required for context switching.
      Furthermore, the problem in the previous method has been solved by finding a CTE value from the 'final_bbl' instead of a randomly found BBL to which we jump.
      Now we know for sure that, say R7 which ought to have value 0x15 in 'final_bbl', will still have that value once we jump to a random BBL.
      * We must choose a random BBL where the selected registers with CTE values are not altered by the random BBL (this isn't implemented here).

    Problem with this method:
      This method should work, unfortunately it is very rare for Diablo's analysis to find a CTE register in the 'final_bbl';
      whenever it cannot find one, it will automatically abort the operation.
      At this stage this method remains incomplete due to this fact.

    For a better solution look at segv_5 and/or segv_6
  */
  protected:
    struct sm4 {
      t_object* obj;
      t_regset available = RegsetNew();
      t_relocatable* target;
      t_bbl* obfus_final_bbl;
    };
    std::vector<sm4*> vm4;

    void obfus_do_const_analysis(t_bbl* bbl, std::vector<std::pair<t_reg, t_uint32>>& vregConst);
    virtual bool obfus_process_stack_get_pairSplit_regB_check(std::pair<t_arm_ins*, s_bbl*>& pairSplit, s_ins* rsins);

  public:
    Obfus_m_segv_4_revised(ObfusData* data, bool enforceDummyInstructions) : Obfus_m_segv_4(data, enforceDummyInstructions) { FATAL(("DEPRECATED")); }
    virtual void postProcess();
    virtual void encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target);
};

// DEPRECATED ::
class Obfus_m_segv_5 			: public Obfus_m_segv_2 {
  // advanced version of m_2: insert dead instructions into a random BBL, then jump to that BBL; the starting value is re-constructed by the dead instructions in to a valid ill_addr_encoded_offset.
  /*
    here is a problem with this method:
      we insert instructions in a BBL which we do not fully control ; it may be a function that is called many times.
      which also means that the regB value in the LDR/STR can, most likely will, result in Segmentation fault unexpectedly.
      this is because the regB can get a value from elsewhere, and chances are it will be a random ill_Addr such as 0x0.

    problem: we are making an assumption about the liveliness of registers in randomly found BBLs
             furthermore we are inserting MOV & SUB instructions; this is the cause of a huge conflict.
    reason:  the normal execution of the BBL makes use of the STR/LDR we found;
             but we are performing a SUB instruction on it;
             our context switch will work just fine, but the  normal execution of that BBL will not!

             is to place the MOV, ADD/SUB instructions before the jump;
              this is a soft-obfuscation strategy, inserting a few instructions to increase complexity slightly.

    For a better solution kindly refer to method segv_6.
  */
  protected:
    void available_with_other_bbl(s_bbl* rbbl, s_ins* rsins, t_regset& available, t_regset& ret);
    unsigned int insert_addr_ins(t_bbl* bbl, bool isThumb, t_regset& regs, t_reg& ill_reg);

  public:
    Obfus_m_segv_5(ObfusData* data, bool enforceDummyInstructions) : Obfus_m_segv_2(data, enforceDummyInstructions) { FATAL(("DEPRECATED")); }
    virtual void encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target);
};

class Obfus_m_segv_6 			: public Obfus_m_segv_2 {
  // simplification of method5
  // notice: a segmentation fault occured while testing bzip2 just once out of 20 runs - bad build ?
  /*
    Method description:
      This method works in the same fashion as segv_2.
      Except that in our 'final_bbl', the BBL where the context switch happens, we add some address instructions.
      The idea is to use the address producer to generate an incorrect ill_addr (it may not even by illegal),
      but these instructions will transform it into the correct ill_addr with offset encoded.

      To furtherly increase randomness, we use a random number of available registers for this method.

      * when enforceDummies is enabled, it will guarantee at least one dummy instruction or generate an error/abort.
        however the number of dummy instructions will be limited, and my tests conclude that at most one dummy instruction is present.
        All other dummy instructions are filtered out since they can alter the state of our available registers etc.
      **This method takes the first possible solution with at least one dummy instruction but it doesn't search for the most optimal one.
  */
  protected:
    unsigned int insert_addr_ins(t_bbl* bbl, bool isThumb, t_regset& regs, t_reg& ill_reg);

  public:
    Obfus_m_segv_6(ObfusData* data, bool enforceDummyInstructions) : Obfus_m_segv_2(data, enforceDummyInstructions) {}
    virtual void encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target);
};

class Obfus_m_segv_7 			: public Obfus_m_segv_6 {
  // advanced version of segv_6 where BBLs' destinations converge
  /*
      Here we go and find a BBL which has an LDR/STR we can jump to.
      Our original BBL will have address instructions, which use a random set of available registers.
      The final instruction is a conditional branch to the LDR/STR bbl; the condition is randomly chosen. If the condition is not met, we continue to the next bbl:
      This next bbl is a new/empty BBL, which also contains another set of random address instructions, but this one eventually jumps to the LDR/STR bbl.

          [ final_bbl ]      --> random condition branch to either A or B
          /            \
         /              \
        /                \
     [bbl A]           [bbl B]  --> both perform different instructions to reconstruct ill_addr_encoded_offset
        \                /
         \              /
          \            /
           [   rbbl   ]          --> this one contains the LDR/STR which causes the context switch

  */

  protected:
    void insert_ctx_code(t_bbl* from_bbl, s_bbl* rbbl, s_ins* rsins, t_arm_condition_code cond, t_relocatable* target, t_regset& rest, bool isThumb, t_object* obj);
    t_arm_condition_code random_cond();

  public:
    Obfus_m_segv_7(ObfusData* data, bool enforceDummyInstructions) : Obfus_m_segv_6(data, enforceDummyInstructions) {}
    virtual void encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target);
};

class Obfus_m_segv_8 			: public Obfus_m_segv_7 {
  // advanced version of segv_7 where BBLs' destinations diverge
  /*
      Here we go and find two(2) BBLs which have an LDR/STR we can jump to.
      Our original BBL will have address instructions, which use a random set of available registers.
      The final instruction is a conditional branch to the first LDR/STR bbl; the condition is randomly chosen. If the condition is not met, we continue to the next bbl:
      This next bbl is a new/empty BBL, which also contains another set of random address instructions, but this one eventually jumps to the other LDR/STR bbl.

          [ final_bbl ]      --> random condition branch to either A or B
          /            \
         /              \
        /                \
     [bbl A]           [bbl B]  --> both perform different instructions to reconstruct ill_addr_encoded_offset
        |                 |
        |                 |
        |                 |
     [rbbl A]          [rbbl B]          --> both contain a LDR/STR which causes the context switch

  */

  protected:
    void find_rbbl(s_bbl*& rbbl, s_ins*& rsins, t_regset& rest, t_bbl* bbl, bool isThumb, t_regset& available, std::vector<s_bbl*>& vfil);
    t_arm_condition_code determine_condition_based_on_flag(t_bbl* bbl);

  public:
    Obfus_m_segv_8(ObfusData* data, bool enforceDummyInstructions) : Obfus_m_segv_7(data, enforceDummyInstructions) {}
    virtual void encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target);
};

class Obfus_m_segv_9      : public Obfus_m_segv_2 {
  // experimental version BX
  /*
    Instead of using a LOAD/STORE, we set out using the BX instruction:
    First we create & load an illegal address with encoded destination address;
    then we add a BX instruction which will attempt to branch to that illegal address.
    --> the PC register changes!! So we cannot encode an offset; only the destination address of the migrated function.

    todo: BLX (branch link exchange) ;
        --> does the Link register get changed? Probably yes ; so we have to push the LR if it's alive and pop it in debugger.
  */
  public:
    Obfus_m_segv_9(ObfusData* data) : Obfus_m_segv_2(data, false) {}
    virtual void encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target);
};

class Obfus_m_segv_10      : public Obfus_m_segv_2 {
  /*
    More advanced version of segv_9 ;
    we construct a mapping of all BX instructions
    we choose a random one, and make sure its first operand gets an illegal address with encoded destination address.
  */
  public:
    Obfus_m_segv_10(ObfusData* data, bool enforceDummyInstructions) : Obfus_m_segv_2(data, enforceDummyInstructions) {}
    virtual void encode_signalling(t_object* obj, t_regset& available, t_bbl* bbl, t_relocatable* target);
};

#endif
