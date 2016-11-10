/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

DEF_ISEL_SEM(RDTSC) {
  memory = __remill_sync_hyper_call(state, memory, SyncHyperCall::kX86ReadTSC);
}

DEF_ISEL_SEM(RDTSCP) {
  memory = __remill_sync_hyper_call(state, memory, SyncHyperCall::kX86ReadTSCP);
}
