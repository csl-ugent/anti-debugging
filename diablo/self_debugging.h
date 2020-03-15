/* This research is supported by the European Union Seventh Framework Programme (FP7/2007-2013), project ASPIRE (Advanced  Software Protection: Integration, Research, and Exploitation), under grant agreement no. 609734; on-line at https://aspire-fp7.eu/. */
/* AUTHORS:
 * Bert Abrath
 * Ilja Nevolin
 * Joris Wijnant
 */

#ifndef _SELFDEBUGGING_MAIN_H_
#define _SELFDEBUGGING_MAIN_H_

#include <memory>
#include <string>
#include <vector>

extern "C" {
#include <diablosupport.h>
#include <diabloanopt.h>
#include <diabloanoptarm.h>
#include <diabloarm.h>
#include <diabloflowgraph.h>
}

#include "self_debugging_cmdline.h"
#include "self_debugging_json.h"

#include <abstract_transformer.h>

class ObfusData;
class SelfDebuggingTransformer : public AbstractTransformer
{
  protected:
    t_symbol* init_sym;/* Symbol for the initialization routine */
    t_symbol* ldr_sym;
    t_symbol* str_sym;
    t_symbol* ldm_sym;
    t_symbol* stm_sym;
    t_function* function_ldm;
    t_function* function_ldr;
    t_function* function_stm;
    t_function* function_str;
    static const bool dump_metrics = false;

    /* Variables for the maps used by the mini-debugger */
    t_symbol* target_map_sym;
    t_section* target_map_sec;
    t_uint32 target_map_entry_size;/* The size of one entry */
    t_symbol* nr_of_targets_sym;/* The number of targets in the map */

    /* The constants used by the map as key */
    std::vector<t_uint32> constants;
    std::vector<t_bool> targets_migrated;
    std::vector<t_arm_ins*> signaling_instructions;

    /* The obfuscator instance */
    std::unique_ptr<ObfusData> obfusData;

    /*** FUNCTIONS ***/
  private:
    /* Private helper functions */
    t_uint32 TargetMapAddEntry(t_relocatable* target, t_bool is_migrated_target);
    void PrepareCfg (t_cfg* cfg);
    void TransformLdm(t_bbl* bbl, t_arm_ins* orig_ins);
    void TransformLdr(t_bbl* bbl, t_arm_ins* orig_ins);
    void TransformStm(t_bbl* bbl, t_arm_ins* orig_ins);
    void TransformStr(t_bbl* bbl, t_arm_ins* orig_ins);

    /* Implement the virtual functions */
    t_bool CanTransformFunction (t_function* fun) const;
    void TransformBbl (t_bbl* bbl);
    void TransformExit (t_cfg_edge* edge);
    void TransformIncomingEdgeImpl (t_bbl* bbl, t_cfg_edge* edge);
    void TransformIncomingTransformedEdgeImpl (t_arm_ins* ins, t_reloc* reloc);
    void TransformOutgoingEdgeImpl (t_bbl* bbl, t_cfg_edge* edge, t_relocatable* to);

  public:
    void AddForceReachables (std::vector<std::string>& reachable_vector);
    void TransformObject ();
    virtual void FinalizeTransform ();/* This function is to be called after deflowgraphing but before assembling of the main object */

    /* Constructor and destructor */
    SelfDebuggingTransformer (t_object* obj, t_const_string output_name);
    ~SelfDebuggingTransformer ();
};

#endif
