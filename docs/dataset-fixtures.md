# Dataset fixture provenance

## LANL authentication affinity sample

Path: `badlands/datasets/lanl_auth_affinity_sample.csv`

Source family: LANL public cyber datasets, `https://csr.lanl.gov/data/`, specifically the user-computer authentication-association use case.

License/access path: public LANL dataset access page. The checked-in fixture is a tiny derived calibration file, not raw LANL records. It preserves only non-sensitive synthetic identifiers and relative affinity fields needed for this vertical slice.

Transformation:

1. Reduce enterprise auth associations to `user_id`, `primary_host`, relative `logons`, and plausible `anomalous_hosts`.
2. Rename users/hosts into Mission Desk enclave identifiers.
3. Keep relative non-uniformity so green auth events follow user-host affinities instead of uniform random selection.

Fields used by code:

- `user_id`: green identity.
- `primary_host`: normal workstation affinity.
- `logons`: relative sampling weight for background auth activity.
- `anomalous_hosts`: future anomaly plausibility and lateral-movement validation.

Test coverage: `test_lanl_fixture_makes_auth_non_uniform` verifies green auth telemetry names the fixture and repeats user-host affinity pairs rather than sampling uniformly across all hosts.
