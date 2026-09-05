/** Create an inert integration template; this function performs no analysis. */
export function buildReviewTemplate(packet) {
  if (packet?.kind !== 'LENS') throw new Error('review-template supports source-review LENS jobs only')
  if (!/^[a-f0-9]{64}$/.test(packet.packet_sha256 ?? '')) {
    throw new Error('review-template requires a controller-bound packet digest')
  }
  const topics = [...(packet.topic_obligations ?? [])]
  const paths = packet.scoped_files ?? []
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/review-handoff',
    analysis_status: 'NOT_PERFORMED',
    input: {
      run_id: packet.run_id,
      job_id: packet.job_id,
      packet_sha256: packet.packet_sha256,
      lens: packet.lens,
      source_file_count: paths.length,
      source_path_examples: paths.slice(0, 20),
      omitted_source_path_count: Math.max(0, paths.length - 20),
    },
    result_schema: 'schemas/job-result.schema.json',
    instructions: [
      'Read the complete matching packet from next, including its trusted lens contract and exact source scope.',
      'Complete producer identity and result state only after conducting the review; null placeholders intentionally fail validation.',
      'Record only actually examined files and supported findings. Give every topic its evidence-backed disposition.',
      'Keep missing or partial work as coverage gaps. An empty findings list does not establish a clean assessment.',
      'Validate the completed result with check-result. Ingest is a separate explicit commit.',
    ],
    result_template: {
      schema_version: '1.0.0',
      run_id: packet.run_id,
      job_id: packet.job_id,
      input_sha256: packet.packet_sha256,
      producer: { name: null, version: null, instance_id: null },
      state: null,
      examined_files: [],
      findings: [],
      coverage_gaps: [{ area: `job:${packet.job_id}`, reason: 'Source review has not been performed.' }],
      ...(topics.length > 0 ? {
        topic_assessments: topics.map((topic) => ({
          topic,
          disposition: 'not-assessed',
          reason: 'Source review has not been performed.',
          coverage_gap_areas: [`job:${packet.job_id}`],
        })),
      } : {}),
    },
  }
}
