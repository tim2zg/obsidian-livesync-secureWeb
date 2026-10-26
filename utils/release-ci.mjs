/** Select the latest push CI run for the exact release commit. */
export function assertReleaseCI(runs, revision) {
    const run = runs.filter(item => item.head_sha === revision && item.event === "push")
        .sort((left, right) => right.run_number - left.run_number)[0];
    if (!run || run.status !== "completed" || run.conclusion !== "success") {
        throw new Error(`Release ${revision} requires its latest push run of unit-ci to complete successfully.`);
    }
    return run;
}
