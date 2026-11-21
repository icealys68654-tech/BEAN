export type C4Type = "Person" | "System" | "Container" | "Component";
export interface C4Element { id: string; name: string; type: C4Type; description?: string; technology?: string }
export interface C4Relationship { source: string; target: string; description: string; technology?: string }
export interface C4Model { elements: C4Element[]; relationships: C4Relationship[] }

export function validate(model: C4Model): string[] {
  const errors: string[] = [];
  const ids = new Set<string>();
  for (const [i, element] of (model.elements ?? []).entries()) {
    if (!element.id?.trim()) errors.push(`elements[${i}].id is required`);
    else if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(element.id)) errors.push(`elements[${i}].id must be a safe PlantUML alias`);
    else if (ids.has(element.id)) errors.push(`duplicate element id: ${element.id}`);
    else ids.add(element.id);
    if (!element.name?.trim()) errors.push(`elements[${i}].name is required`);
    if (!["Person", "System", "Container", "Component"].includes(element.type)) errors.push(`elements[${i}].type is invalid`);
  }
  for (const [i, rel] of (model.relationships ?? []).entries()) {
    if (!ids.has(rel.source)) errors.push(`relationships[${i}] missing source: ${rel.source}`);
    if (!ids.has(rel.target)) errors.push(`relationships[${i}] missing target: ${rel.target}`);
    if (!rel.description?.trim()) errors.push(`relationships[${i}].description is required`);
  }
  return errors;
}

const quote = (value: string): string => value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\r?\n/g, " ");
export function toPlantUML(model: C4Model): string {
  const errors = validate(model);
  if (errors.length) throw new Error(`Invalid C4 model:\n- ${errors.join("\n- ")}`);
  const lines = ["@startuml", "!include <C4/C4_Container>", "LAYOUT_WITH_LEGEND"];
  for (const e of model.elements) {
    const fn = ({ Person: "Person", System: "System", Container: "Container", Component: "Component" } as const)[e.type];
    const args = [e.id, `"${quote(e.name)}"`, `"${quote(e.description ?? "")}"`];
    lines.push(`${fn}(${args.join(", ")})`);
  }
  for (const r of model.relationships) lines.push(`Rel(${r.source}, ${r.target}, "${quote(r.description)}", "${quote(r.technology ?? "")}")`);
  lines.push("@enduml");
  return lines.join("\n");
}
