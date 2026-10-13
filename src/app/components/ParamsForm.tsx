import type { OperationSpec, ParamProperty, Params } from "../../core/operation/types";

export function defaultParams(spec: OperationSpec): Params {
  const params: Params = {};
  for (const [name, property] of Object.entries(spec.parametersSchema.properties)) {
    if (property.default !== undefined) params[name] = property.default;
  }
  return params;
}

const INPUT_CLASS = "rounded border border-slate-300 bg-white px-2 py-1 text-sm focus:border-sky-500 focus:outline-none";

interface Props {
  spec: OperationSpec;
  value: Params;
  onChange: (value: Params) => void;
}

/** Form generated from the operation's parameter schema; validation happens in the executor. */
export function ParamsForm({ spec, value, onChange }: Props) {
  const entries = Object.entries(spec.parametersSchema.properties);
  if (entries.length === 0) return <p className="text-sm text-slate-500">No parameters.</p>;

  const set = (name: string, next: unknown) => onChange({ ...value, [name]: next });

  const control = (name: string, property: ParamProperty) => {
    switch (property.type) {
      case "boolean":
        return (
          <input type="checkbox" checked={Boolean(value[name])} onChange={(event) => set(name, event.target.checked)} />
        );
      case "string":
        if (property.enum) {
          return (
            <select className={INPUT_CLASS} value={String(value[name] ?? "")} onChange={(event) => set(name, event.target.value)}>
              {property.enum.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          );
        }
        if (property.multiline) {
          return (
            <>
              <textarea
                className={`${INPUT_CLASS} h-48 resize-y font-mono text-xs`}
                spellCheck={false}
                aria-label={property.title ?? name}
                value={String(value[name] ?? "")}
                onChange={(event) => set(name, event.target.value)}
              />
              <span className="text-xs text-slate-500">
                <label className="cursor-pointer text-sky-700 hover:underline">
                  Load from file…
                  <input
                    type="file"
                    className="hidden"
                    onChange={(event) => {
                      const file = event.target.files?.[0];
                      event.target.value = "";
                      if (file) void file.text().then((text) => set(name, text));
                    }}
                  />
                </label>
              </span>
            </>
          );
        }
        return (
          <input
            className={`${INPUT_CLASS} font-mono`}
            type="text"
            value={String(value[name] ?? "")}
            onChange={(event) => set(name, event.target.value)}
          />
        );
      case "integer":
      case "number":
        return (
          <input
            className={INPUT_CLASS}
            type="number"
            min={property.minimum}
            max={property.maximum}
            step={property.type === "integer" ? 1 : "any"}
            value={value[name] === undefined ? "" : String(value[name])}
            onChange={(event) => set(name, event.target.value === "" ? undefined : Number(event.target.value))}
          />
        );
    }
  };

  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {entries.map(([name, property]) => (
        <label
          key={name}
          className={`flex flex-col gap-1 text-sm ${property.type === "string" && property.multiline ? "sm:col-span-2" : ""}`}
          title={property.description}
        >
          <span className="text-slate-600">{property.title ?? name}</span>
          {control(name, property)}
        </label>
      ))}
    </div>
  );
}
