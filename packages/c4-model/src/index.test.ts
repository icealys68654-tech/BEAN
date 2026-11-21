import { test } from "node:test";
import { strict as assert } from "node:assert";
import { validate, toPlantUML, type C4Model } from "./index";

const model: C4Model = {
  elements: [{ id: "user", name: "Operator", type: "Person" }, { id: "bean", name: "BEAN", type: "System" }],
  relationships: [{ source: "user", target: "bean", description: "operates" }]
};
test("validates relationships and renders PlantUML", () => {
  assert.deepEqual(validate(model), []);
  assert.match(toPlantUML(model), /Person\(user/);
});
test("rejects duplicate ids and missing endpoints", () => {
  const invalid = { ...model, elements: [...model.elements, model.elements[0]], relationships: [{ source: "ghost", target: "bean", description: "" }] };
  assert.ok(validate(invalid).some(x => x.includes("duplicate element id")));
  assert.ok(validate(invalid).some(x => x.includes("missing source")));
});
