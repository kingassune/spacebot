# Metrics

Prometheus-compatible metrics endpoint. Opt-in via the `metrics` cargo feature flag.

## Building with Metrics

```bash
cargo build --release --features metrics
```

Without the feature flag, all telemetry code is compiled out. The `[metrics]` config block is parsed regardless but has no effect.

## Configuration

```toml
[metrics]
enabled = true
port = 9090
bind = "0.0.0.0"
```

| Key       | Default     | Description                          |
| --------- | ----------- | ------------------------------------ |
| `enabled` | `false`     | Enable the /metrics HTTP endpoint    |
| `port`    | `9090`      | Port for the metrics server          |
| `bind`    | `"0.0.0.0"` | Address to bind the metrics server  |

The metrics server runs as a separate tokio task alongside the main API server. It shuts down gracefully with the rest of the process.

## Endpoints

| Path       | Description                              |
| ---------- | ---------------------------------------- |
| `/metrics` | Prometheus text exposition format (0.0.4)|
| `/health`  | Returns 200 OK (for liveness probes)     |

## Exposed Metrics

All metrics are prefixed with `james_`.

### LLM Metrics

| Metric                                  | Type      | Labels                              | Description                        |
| --------------------------------------- | --------- | ----------------------------------- | ---------------------------------- |
| `james_llm_requests_total`           | Counter   | agent_id, model, tier               | Total LLM completion requests      |
| `james_llm_request_duration_seconds` | Histogram | agent_id, model, tier               | LLM request duration               |
| `james_llm_tokens_total`             | Counter   | agent_id, model, tier, direction    | Token counts (input/output/cached)  |
| `james_llm_estimated_cost_dollars`   | Counter   | agent_id, model, tier               | Estimated cost in USD              |

The `tier` label corresponds to the process type making the request: `channel`, `branch`, `worker`, `compactor`, or `cortex`.

### Tool Metrics

| Metric                                    | Type      | Labels                | Description                         |
| ----------------------------------------- | --------- | --------------------- | ----------------------------------- |
| `james_tool_calls_total`               | Counter   | agent_id, tool_name   | Total tool calls executed           |
| `james_tool_call_duration_seconds`     | Histogram |                       | Tool call execution duration        |

### Agent & Worker Metrics

| Metric                                  | Type      | Labels                              | Description                        |
| --------------------------------------- | --------- | ----------------------------------- | ---------------------------------- |
| `james_active_workers`               | Gauge     | agent_id                            | Currently active workers           |
| `james_active_branches`              | Gauge     | agent_id                            | Currently active branches          |
| `james_worker_duration_seconds`      | Histogram | agent_id, worker_type               | Worker lifetime duration           |
| `james_process_errors_total`         | Counter   | agent_id, process_type, error_type  | Process errors by type             |

### Memory Metrics

| Metric                                  | Type      | Labels                | Description                        |
| --------------------------------------- | --------- | --------------------- | ---------------------------------- |
| `james_memory_reads_total`           | Counter   |                       | Total memory recall operations     |
| `james_memory_writes_total`          | Counter   |                       | Total memory save operations       |
| `james_memory_entry_count`           | Gauge     | agent_id              | Memory entries per agent           |
| `james_memory_updates_total`         | Counter   | agent_id, operation   | Memory mutations (save/delete/forget) |

## Useful PromQL Queries

**Total estimated spend by agent:**
```promql
sum(james_llm_estimated_cost_dollars) by (agent_id)
```

**Hourly spend rate by model:**
```promql
sum(rate(james_llm_estimated_cost_dollars[1h])) by (agent_id, model) * 3600
```

**Token throughput:**
```promql
sum(rate(james_llm_tokens_total[5m])) by (direction)
```

**Active branches and workers:**
```promql
james_active_branches
james_active_workers
```

## Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: james
    scrape_interval: 15s
    static_configs:
      - targets: ["localhost:9090"]
```

## Docker

Expose the metrics port alongside the API port:

```bash
docker run -d \
  --name james \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  -v james-data:/data \
  -p 19898:19898 \
  -p 9090:9090 \
  ghcr.io/spacedriveapp/james:slim
```

The Docker image must be built with `--features metrics` for this to work. The default images do not include metrics support.
