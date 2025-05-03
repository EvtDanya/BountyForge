from bountyforge.core.task import run_scan_task

fake_request = {
  "target": ["127.0.0.1"],
  "target_type": "single",
  "tools": ["nmap"],
  "params": {"nmap": {"scan_type":"default","additional_flags":[]}}
}
res = run_scan_task(fake_request)
print(res)