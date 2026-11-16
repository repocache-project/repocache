# One repository route / metrics candidate (#28, #29)

This increment uses the existing closed declarative install-v1 document,
strict numeric upstream pin renderer and approved opt-in NGINX metrics
generator to produce one deterministic pair of HTTP and server fragments.
Each metrics directive is inserted into exactly the one generated
"location ^~ /__repocache/repos/ID/" block for its original repository ID.
The code refuses unmatched IDs, ambiguous marker occurrences, bad pins,
stale generation, unsupported inputs and oversized combined candidates.
Disabled repositories cannot acquire independent logging routes; opt-out
leaves routes intact without enabling metrics.

This is a source-only, deliberately inert candidate join. An unknown
existing NGINX audit log is not overwritten; the result explicitly flags
audit inheritance, state authorization, live exposure, nginx -t and
activation as NOT VERIFIED. A future owner-authorized privileged
transaction must preserve existing required audit logs when adding metrics
inside NGINX location blocks, validate the exact installed stock NGINX,
and publish discovery only from successfully active state.

The existing independent Debian13/Alma10 CI runs already prove real
generated-route cache HIT and opt-in structured NGINX metrics. This PR
regresses their *combined source contract* and adds its own native NGINX
syntax verification in disposable containers. Neither test is a booted
service or a production activation/authorization proof.
