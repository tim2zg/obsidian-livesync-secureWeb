import { serialized } from "octagonal-wheels/concurrency/lock";
import type { NecessaryServices } from "@vrtmrz/livesync-commonlib/compat/interfaces/ServiceModule";
import { isReplicationCompleted, type ReplicatorInstance } from "@vrtmrz/livesync-commonlib/replication";

type MaintenanceServices = NecessaryServices<
    "appLifecycle" | "replication" | "replicator" | "fileProcessing" | "control",
    never
>["services"];

/** Keep automatic transfers paused until maintenance releases its admitted provider. */
export async function withMaintenanceReplication<T>(
    services: MaintenanceServices,
    task: (replicator: ReplicatorInstance) => Promise<T>
): Promise<T> {
    const wasSuspended = services.appLifecycle.isSuspended();
    if (!wasSuspended) services.appLifecycle.setSuspended(true);
    try {
        // The readiness gate observes this lock, fencing new typed transfers.
        // Maintenance's explicit pre-sync and final push run inside this boundary.
        return await serialized("cleanup", async () => {
            const stopped = await services.replication.stopActiveTransfer();
            if (!isReplicationCompleted(stopped)) {
                throw new Error("The active replication could not be stopped for maintenance.");
            }
            if (!(await services.fileProcessing.commitPendingFileEvents())) {
                throw new Error("Pending local file changes could not be saved before maintenance.");
            }
            let admitted = false;
            const result = await services.replicator.runWithActiveReplicatorContext(async (context) => {
                admitted = true;
                return await task(context.replicator);
            });
            if (!admitted) throw new Error("No active replicator is available for maintenance.");
            return result as T;
        });
    } finally {
        // Resume after both provider admission and the cleanup lock have settled.
        // Preserve a pause which existed before the maintenance request.
        if (!wasSuspended) {
            services.appLifecycle.setSuspended(false);
            await services.control.applySettings();
        }
    }
}
