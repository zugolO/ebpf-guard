# Governance

This document describes the governance structure for the ebpf-guard project.

## Overview

ebpf-guard is an open-source project that welcomes contributions from anyone. This governance model aims to balance the need for consistent direction with the benefits of community involvement.

## Roles

### Users

Anyone who uses ebpf-guard. Users can:
- Report bugs and request features via GitHub issues
- Participate in discussions
- Contribute documentation or code

### Contributors

Individuals who contribute to the project. Contributors can:
- Submit pull requests
- Review pull requests
- Participate in design discussions
- Help with documentation

To become a contributor, simply submit a PR that is merged.

### Maintainers

Maintainers have commit access and are responsible for:
- Reviewing and merging pull requests
- Setting technical direction
- Making release decisions
- Enforcing the code of conduct
- Mentoring contributors

#### Current Maintainers

| Name | GitHub | Organization | Areas |
|------|--------|--------------|-------|
| TBD | @maintainer1 | Independent | Core, eBPF |
| TBD | @maintainer2 | Independent | Collectors, CLI |

*See [MAINTAINERS.md](MAINTAINERS.md) for the current list.*

#### Becoming a Maintainer

To become a maintainer:

1. **Demonstrate sustained contribution** over at least 6 months
2. **Show good judgment** in code reviews and discussions
3. **Understand the codebase** across multiple components
4. **Be nominated** by an existing maintainer
5. **Be approved** by a majority of existing maintainers

The nomination should include:
- Summary of contributions
- Examples of code reviews
- Areas of expertise

### Project Lead

The project lead (initially the founder) has final decision authority on:
- Architecture changes
- Release schedules
- Security incident response
- CNCF interactions

The project lead can be changed via a 2/3 vote of maintainers.

## Decision Making

### Consensus-Based

Most decisions are made through consensus in:
- GitHub issues and discussions
- Pull request reviews
- Community meetings (when established)

### Lazy Consensus

For minor changes, lazy consensus applies:
- Propose a change
- Wait 72 hours for objections
- If no objections, proceed

### Formal Votes

Formal votes are required for:
- Adding/removing maintainers
- Major architectural changes
- Breaking API changes
- License changes

Voting:
- Each maintainer gets one vote
- Simple majority (50% + 1) for most decisions
- 2/3 majority for governance changes

## Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):
- `MAJOR.MINOR.PATCH`
- Major: Breaking changes
- Minor: New features (backward compatible)
- Patch: Bug fixes

### Release Cadence

- **Patch releases**: As needed for critical bugs
- **Minor releases**: Every 4-6 weeks
- **Major releases**: As needed, with deprecation period

### Release Steps

1. Create a release branch `release-X.Y`
2. Update version numbers and CHANGELOG
3. Tag with `vX.Y.Z`
4. CI builds and publishes artifacts
5. Create GitHub release with notes
6. Announce in community channels

## Roadmap

The project roadmap is maintained in:
- [GitHub Milestones](https://github.com/zugolO/ebpf-guard/milestones)
- [Task.md](Task.md) - Detailed sprint planning

### Roadmap Ownership

- Maintainers propose roadmap items
- Community input via GitHub Discussions
- Project lead prioritizes
- Roadmap reviewed quarterly

## Conflict Resolution

If consensus cannot be reached:

1. **Discuss** the issue in a dedicated GitHub issue
2. **Escalate** to maintainers if needed
3. **Vote** if maintainers are split
4. **Project lead** decides if vote is tied

All parties are expected to remain respectful and accept the outcome.

## Code of Conduct

All participants must follow our [Code of Conduct](CODE_OF_CONDUCT.md). Violations should be reported to the maintainers.

## Changes to Governance

Changes to this document require:
1. PR with proposed changes
2. Discussion period of at least 1 week
3. 2/3 vote of maintainers
4. Project lead approval

## CNCF Alignment

As a CNCF Sandbox project (aspiring), we follow CNCF principles:

- **Openness**: All discussions and decisions in public
- **Neutrality**: No single vendor control
- **Meritocracy**: Recognition based on contribution
- **Inclusivity**: Welcoming to all contributors

## Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and design discussions
- **Pull Requests**: Code review and technical discussion
- **Security**: security@ebpf-guard.io (or maintainer emails)

## Meetings

Currently, all discussion happens asynchronously via GitHub. We may establish regular community meetings as the project grows.

## Acknowledgments

This governance model is inspired by:
- [CNCF Project Governance](https://github.com/cncf/project-template/blob/main/GOVERNANCE-maintainer.md)
- [Falco Governance](https://github.com/falcosecurity/falco/blob/master/GOVERNANCE.md)
- [Kubernetes Governance](https://github.com/kubernetes/community/blob/master/governance.md)
