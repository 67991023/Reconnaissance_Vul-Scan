import concurrent.futures
from dataclasses import dataclass
from pathlib import Path

from superecon.plugins.registry import registry
from superecon.dataModel import Port, PluginResult

@dataclass
class PluginTask:
    plugin_name: str
    target_host: str
    port: Port
    output_dir: Path

def _run_single_plugin(task: PluginTask) -> PluginResult:
    plugin_class = registry.get(task.plugin_name)
    plugin_instance = plugin_class()
    return plugin_instance.run(task.target_host, task.port, task.output_dir)

def run_plugins_concurrently(
    tasks: list[PluginTask],
    max_workers: int = 5,
    timeout_seconds: int = 120,
) -> list[PluginResult]:
    results: list[PluginResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_task = {executor.submit(_run_single_plugin, task): task for task in tasks}
        for future in concurrent.futures.as_completed(future_to_task, timeout=timeout_seconds):
            task = future_to_task[future]
            try:
                result = future.result(timeout=timeout_seconds)
                results.append(result)
            except concurrent.futures.TimeoutError:
                print(f"  [timeout] {task.plugin_name} บน port {task.port.number}")
            except Exception as e:
                print(f"  [error] {task.plugin_name} บน port {task.port.number}: {e}")
    return results