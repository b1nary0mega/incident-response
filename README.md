# ...Notes...
## Required files
### 01-Pull_Machine_Info.ps1
_IRDumper.psm1_ - get-adcomputer module is required to leverage certain parts of this module (LAPS and AD Information)
### JCERT.ps1
_NONE_ - no pre-requisite files

## IR PHASES:
[ ] Preparation : Ensuring you have the appropriate response plans, policies, call trees and other documents in place, and that you have identified the members of your incident response team including external entities.
[ ] Identification : Work out whether you are dealing with an event or an incident. This is where understanding your environment is critical as it means looking for significant deviations from "normal" traffic baselines or other methods.
[ ] Containment : Heading into the containment stage, work with the business to limit the damage caused to systems and prevent any further damage from occurring. This includes short and long term containment activities.
[ ] Eradication : Ensure you have a clean system ready to restore. This may be a complete reimage of a system, or a restore from a known good backup.
[ ] Recovery : Determine when to bring the system back in to production and how long we monitor the system for any signs of abnormal activity.
[ ] Lessons Learned : Often skipped but critical, is to look back and heed the lessons learned. Incorporate additional activities and knowledge back into your incident response process to produce better future outcomes and additional defenses.

## NOTES:
### Recommended Order of Operations
[ ] Enumerate Files
[ ] Collect network caches
[ ] Collect Users
[ ] Analyze Startup Items
[ ] Analyze Programs Run
[ ] Collect Network Shares
[ ] Collect System Configuration
[ ] Analyze Scheduled tasks
[ ] Analyze event logs
[ ] Collect Processes
[ ] Collect Network Connections and Ports
[ ] Collect web files
[ ] Analyze all files