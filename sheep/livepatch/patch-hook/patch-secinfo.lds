__livepatch_funcs = ADDR(.livepatch.funcs);
__livepatch_funcs_end = ADDR(.livepatch.funcs) + SIZEOF(.livepatch.funcs);
__livepatch_dynrelas = ADDR(.livepatch.dynrelas);
__livepatch_dynrelas_end = ADDR(.livepatch.dynrelas) + SIZEOF(.livepatch.dynrelas);
SECTIONS
{
  .lp_init_text : {
    *(.lp_init_text)
    QUAD(0);
  }
  .lp_exit_text : {
    *(.lp_exit_text)
    QUAD(0);
  }
}
