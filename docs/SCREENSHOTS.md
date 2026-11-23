# Visual capture policy

Noxmap distinguishes real runtime captures from design-direction artwork.
This protects users from confusing a proposed surface with a shipped feature.

| Asset | Classification | What it shows |
| --- | --- | --- |
| [`screenshots/noxmap-desktop-concept.png`](screenshots/noxmap-desktop-concept.png) | Design direction | An original visual direction for a future expanded desktop workspace. It is not a runtime screenshot. |

The checked-in desktop binary has a working Scan workspace. Capture release
screenshots only from that binary after selecting a safe loopback target, and
name future captures `noxmap-desktop-<version>-<surface>.png`. Do not include
private hosts, public IP addresses, credential prompts, or unrelated desktop
content in a repository screenshot.

