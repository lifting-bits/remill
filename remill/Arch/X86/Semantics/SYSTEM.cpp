/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

namespace {

DEF_SEM(DoRDTSC) {
  memory = __remill_sync_hyper_call(memory, state, SyncHyperCall::kX86ReadTSC);
  return memory;
}

DEF_SEM(DoRDTSCP) {
  memory = __remill_sync_hyper_call(memory, state, SyncHyperCall::kX86ReadTSCP);
  return memory;
}
}  // namespace


DEF_ISEL(RDTSC) = DoRDTSC;

DEF_ISEL(RDTSCP) = DoRDTSCP;
