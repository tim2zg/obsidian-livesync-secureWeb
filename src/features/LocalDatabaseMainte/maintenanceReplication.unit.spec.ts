import { describe, expect, it, vi } from "vitest";
import { isLockAcquired } from "octagonal-wheels/concurrency/lock";
import { withMaintenanceReplication } from "./maintenanceReplication";

function fixture(initiallySuspended = false) {
    let suspended = initiallySuspended;
    let admitted = false;
    const provider = {};
    const services = {
        appLifecycle: {
            isSuspended: vi.fn(() => suspended),
            setSuspended: vi.fn((value: boolean) => {
                suspended = value;
            }),
        },
        replication: { stopActiveTransfer: vi.fn(async (): Promise<{ status: string }> => ({ status: "completed" })) },
        fileProcessing: { commitPendingFileEvents: vi.fn(async () => true) },
        replicator: {
            runWithActiveReplicatorContext: vi.fn(async (task: (context: { replicator: object }) => unknown) => {
                admitted = true;
                try {
                    return await task({ replicator: provider });
                } finally {
                    admitted = false;
                }
            }),
        },
        control: {
            applySettings: vi.fn(async () => {
                expect(admitted).toBe(false);
                expect(isLockAcquired("cleanup")).toBe(false);
                expect(suspended).toBe(false);
            }),
        },
    };
    const run = <T>(task: (replicator: object) => Promise<T>) =>
        withMaintenanceReplication(services as unknown as Parameters<typeof withMaintenanceReplication>[0], task);
    return { services, provider, run, isSuspended: () => suspended };
}

describe("maintenance replication ownership", () => {
    it("stops continuous sync, saves pending edits, and holds the cleanup fence until the provider is released", async () => {
        const f = fixture();
        const task = vi.fn(async (provider) => {
            expect(provider).toBe(f.provider);
            expect(f.isSuspended()).toBe(true);
            expect(isLockAcquired("cleanup")).toBe(true);
            expect(f.services.replication.stopActiveTransfer).toHaveBeenCalledOnce();
            expect(f.services.fileProcessing.commitPendingFileEvents).toHaveBeenCalledOnce();
            return "cancelled by user";
        });
        expect(await f.run(task)).toBe("cancelled by user");
        expect(f.services.replication.stopActiveTransfer.mock.invocationCallOrder[0]).toBeLessThan(
            f.services.fileProcessing.commitPendingFileEvents.mock.invocationCallOrder[0]
        );
        expect(f.services.fileProcessing.commitPendingFileEvents.mock.invocationCallOrder[0]).toBeLessThan(
            task.mock.invocationCallOrder[0]
        );
        expect(f.services.control.applySettings).toHaveBeenCalledOnce();
    });

    it("restores automatic sync when maintenance throws", async () => {
        const f = fixture();
        await expect(
            f.run(async () => {
                throw new Error("pre-sync failed");
            })
        ).rejects.toThrow("pre-sync failed");
        expect(f.isSuspended()).toBe(false);
        expect(f.services.control.applySettings).toHaveBeenCalledOnce();
    });

    it("preserves a pause which was already active", async () => {
        const f = fixture(true);
        await f.run(async () => true);
        expect(f.isSuspended()).toBe(true);
        expect(f.services.appLifecycle.setSuspended).not.toHaveBeenCalled();
        expect(f.services.control.applySettings).not.toHaveBeenCalled();
    });

    it("does not enter maintenance when the active transfer cannot be stopped", async () => {
        const f = fixture();
        f.services.replication.stopActiveTransfer.mockResolvedValue({ status: "failed" });
        const task = vi.fn();
        await expect(f.run(task)).rejects.toThrow("could not be stopped");
        expect(task).not.toHaveBeenCalled();
        expect(f.services.fileProcessing.commitPendingFileEvents).not.toHaveBeenCalled();
        expect(f.services.control.applySettings).toHaveBeenCalledOnce();
    });

    it("does not enter maintenance while accepted file edits cannot be saved", async () => {
        const f = fixture();
        f.services.fileProcessing.commitPendingFileEvents.mockResolvedValue(false);
        const task = vi.fn();
        await expect(f.run(task)).rejects.toThrow("could not be saved");
        expect(task).not.toHaveBeenCalled();
        expect(f.services.control.applySettings).toHaveBeenCalledOnce();
    });

    it("restores sync if stopping the active transfer throws", async () => {
        const f = fixture();
        f.services.replication.stopActiveTransfer.mockRejectedValueOnce(new Error("stop failed"));
        const task = vi.fn();
        await expect(f.run(task)).rejects.toThrow("stop failed");
        expect(task).not.toHaveBeenCalled();
        expect(f.services.control.applySettings).toHaveBeenCalledOnce();
    });

    it("refuses maintenance when no provider admission can be acquired", async () => {
        const f = fixture();
        f.services.replicator.runWithActiveReplicatorContext.mockResolvedValueOnce(undefined);
        const task = vi.fn();
        await expect(f.run(task)).rejects.toThrow("No active replicator");
        expect(task).not.toHaveBeenCalled();
        expect(f.services.control.applySettings).toHaveBeenCalledOnce();
    });
});
