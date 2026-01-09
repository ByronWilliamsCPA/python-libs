# Diagram Specialist Agent

A specialized Claude Code agent for generating professional technical diagrams, blueprints,
and visual documentation using the gemini-image library.

## Agent Profile

```yaml
name: diagram-specialist
description: Generates professional technical diagrams and visual documentation
tools:
  - gemini-image CLI
  - Read/Write for prompt refinement
  - Bash for image management
```

## Capabilities

1. **Architecture Diagrams** - System architecture, microservices, cloud infrastructure
2. **Data Flow Diagrams** - ETL pipelines, data governance flows, integration patterns
3. **Process Diagrams** - Business processes, workflows, decision trees
4. **Technical Blueprints** - API designs, database schemas, network topologies
5. **Organizational Charts** - Team structures, reporting hierarchies
6. **Timeline Visualizations** - Project roadmaps, implementation phases

## Usage Patterns

### Single Diagram Generation

```bash
# Generate a simple architecture diagram
gemini-image "A microservices architecture diagram showing API gateway, auth service, user service, and database layer with clear labels" \
  --model pro \
  --aspect 16:9 \
  --size 2K \
  -o architecture.png
```

### Draft-Then-Finalize Workflow

For complex diagrams requiring iteration:

```bash
# 1. Quick draft for structure validation
gemini-image "Data governance lifecycle diagram with data collection, classification, storage, and archival stages" \
  --draft-mode \
  -o governance_draft.png

# 2. Review and refine
gemini-image "Refine the diagram: add compliance checkpoints between each stage, use blue color scheme" \
  -r governance_draft.png \
  --draft-mode \
  -o governance_v2.png

# 3. Finalize at production quality
gemini-image --finalize governance_v2.png --size 2K -o governance_final.png
```

### Multi-Part Documentation Set

Generate a series of related diagrams:

```bash
gemini-image "A data platform architecture evolution: from monolithic to microservices to serverless" \
  --story-parts 3 \
  --aspect 16:9 \
  -o platform_evolution
```

### Batch Documentation Generation

Create a JSON file for systematic documentation:

```json
[
  {
    "prompt": "System context diagram showing external users, APIs, and third-party integrations",
    "aspect_ratio": "16:9",
    "output_path": "01_context.png"
  },
  {
    "prompt": "Container diagram showing web app, API layer, message queue, and databases",
    "aspect_ratio": "16:9",
    "output_path": "02_containers.png"
  },
  {
    "prompt": "Component diagram showing authentication, authorization, and user management modules",
    "aspect_ratio": "16:9",
    "output_path": "03_components.png"
  },
  {
    "prompt": "Deployment diagram showing Kubernetes pods, load balancers, and cloud services",
    "aspect_ratio": "16:9",
    "output_path": "04_deployment.png"
  }
]
```

```bash
gemini-image --batch c4_diagrams.json -d ./docs/diagrams
```

## Prompt Engineering Guidelines

### Effective Diagram Prompts

**DO:**

- Specify diagram type explicitly: "architecture diagram", "flowchart", "sequence diagram"
- Include all components and their relationships
- Request clear labels and annotations
- Specify color schemes or visual styles
- Mention target audience (technical, executive, etc.)

**DON'T:**

- Use vague descriptions like "a nice diagram"
- Omit relationship types between components
- Forget to specify text readability requirements
- Request too many elements in one diagram

### Prompt Templates

**Architecture Diagram:**

```text
A [type] architecture diagram showing:
- [Component 1] with [responsibilities]
- [Component 2] connected to [Component 1] via [connection type]
- [Component 3] for [purpose]
Use [color scheme] color scheme with clear labels and arrows indicating data flow.
Style: professional, clean, suitable for [audience].
```

**Data Flow Diagram:**

```text
A data flow diagram illustrating [process name]:
1. [Source] produces [data type]
2. [Processor] transforms data using [method]
3. [Destination] stores/consumes the result
Include validation checkpoints and error handling paths.
Use icons where appropriate.
```

**Process Flowchart:**

```text
A business process flowchart for [process name]:
- Start: [trigger event]
- Decision points: [list key decisions]
- Endpoints: [success and failure outcomes]
Use standard flowchart symbols with clear decision labels.
```

## Integration Examples

### Python Script for Documentation Generation

```python
#!/usr/bin/env python3
"""Generate project documentation diagrams."""

from pathlib import Path
from gemini_image import generate_batch, generate_image

# Define documentation structure
docs_dir = Path("./docs/diagrams")
docs_dir.mkdir(parents=True, exist_ok=True)

# Single high-priority diagram
overview = generate_image(
    prompt="""
    System overview diagram showing:
    - Web frontend (React)
    - API Gateway (Kong)
    - Microservices (User, Order, Payment)
    - Message Queue (RabbitMQ)
    - Databases (PostgreSQL, Redis)
    Professional style with technology logos and data flow arrows.
    """,
    model_key="pro",
    aspect_ratio="16:9",
    image_size="2K",
    output_dir=docs_dir,
    output_path=docs_dir / "system_overview.png",
)
print(f"Generated: {overview}")

# Batch generate supporting diagrams
supporting_diagrams = [
    {
        "prompt": "Authentication flow: user login, JWT generation, token validation, session management",
        "aspect_ratio": "16:9",
        "output_path": "auth_flow.png",
    },
    {
        "prompt": "Database schema: users, orders, products, payments tables with relationships",
        "aspect_ratio": "4:3",
        "output_path": "database_schema.png",
    },
    {
        "prompt": "CI/CD pipeline: code commit, build, test, deploy stages with tool icons",
        "aspect_ratio": "16:9",
        "output_path": "cicd_pipeline.png",
    },
]

results = generate_batch(
    prompts=supporting_diagrams,
    output_dir=docs_dir,
    show_progress=True,
)

for prompt, result in zip(supporting_diagrams, results):
    if result:
        print(f"Generated: {result}")
    else:
        print(f"Failed: {prompt['output_path']}")
```

### Claude Code Integration

When used within Claude Code, this agent can:

1. **Analyze Codebase** - Read code structure and generate accurate diagrams
2. **Update Documentation** - Regenerate diagrams when architecture changes
3. **Validate Consistency** - Ensure diagrams match implementation
4. **Version Control** - Track diagram changes via PROMPTS.md registry

Example Claude Code workflow:

```text
User: Generate architecture diagrams for this project

Agent:
1. Analyze src/ directory structure
2. Identify key components and dependencies
3. Generate context, container, and component diagrams
4. Save to docs/diagrams/ with metadata
5. Update README.md with diagram references
```

## Quality Checklist

Before finalizing diagrams, verify:

- [ ] All components are labeled clearly
- [ ] Relationships have descriptive labels
- [ ] Color scheme is consistent
- [ ] Text is readable at expected display size
- [ ] Diagram type matches content (flowchart vs. architecture)
- [ ] Level of detail appropriate for audience
- [ ] No overlapping elements
- [ ] Consistent iconography throughout

## Troubleshooting

### Text Not Readable

Use Pro model with 2K+ resolution:

```bash
gemini-image "..." --model pro --size 2K
```

### Too Much Detail

Split into multiple diagrams using story sequences or batch processing.

### Inconsistent Style

Use reference images for style continuity:

```bash
gemini-image "New diagram in same style" -r existing_style.png
```

### Complex Relationships

Use draft mode to iterate on layout:

```bash
gemini-image "..." --draft-mode -o draft.png
# Review and refine
gemini-image "Move component X to the left, add more spacing" -r draft.png --draft-mode -o draft_v2.png
```
