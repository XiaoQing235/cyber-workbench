import { describe, expect, it } from "vitest";
import { detectLanguage, unpackScript } from "./script";

const utf16Base64 = (text: string) => btoa(String.fromCharCode(...new Uint8Array(new Uint16Array([...text].map((c) => c.charCodeAt(0))).buffer)));

describe("script unpacker", () => {
  it("unpacks Dean Edwards' packer without running it", () => {
    // Output of the real packer for: var flag="flag{packed}";console.log(flag);
    const packed = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e]}];e=function(){return'\\\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('3 0=\"0{2}\";4.1(0);',5,5,'flag|log|packed|var|console'.split('|'),0,{}))";
    const result = unpackScript(packed, "auto");
    expect(result.text).toBe('var flag="flag{packed}";console.log(flag);');
    expect(result.applied[0]).toEqual({ rule: "Dean Edwards packer", count: 1 });
  });

  it("folds layered JavaScript string tricks", () => {
    const source = [
      "var a = String.fromCharCode(102, 108, 97, 103);",
      "var b = atob('e2pzXw==') + '\\x6c\\x61' + \"yers}\";",
      'var c = "}desrever{".split("").reverse().join("");',
      'document.write(unescape("%66%6c%61%67"));',
    ].join("\n");
    const { text, language } = unpackScript(source, "auto");
    expect(language).toBe("javascript");
    expect(text).toContain('var a = "flag";');
    expect(text).toContain('var b = "{js_layers}";');
    expect(text).toContain('var c = "{reversed}";');
    expect(text).toContain('document.write("flag");');
  });

  it("decodes PowerShell -EncodedCommand and the obfuscation inside it", () => {
    const inner = "$s = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('ZmxhZ3twc30=')); I`Nv`oke-Ex`pression ('{1}{0}' -f 'world','hello ') + [char]33";
    const wrapper = `powershell.exe -NoP -W Hidden -enc ${utf16Base64(inner)}`;
    expect(detectLanguage(wrapper)).toBe("powershell");
    const { text, applied } = unpackScript(wrapper, "auto");
    expect(text).toContain("$s = 'flag{ps}';");
    expect(text).toContain("INvoke-Expression 'hello world!'");
    expect(applied.map((item) => item.rule)).toEqual(
      expect.arrayContaining(["-EncodedCommand", "FromBase64String", "-f format reordering", "[char] codes", "backtick noise"]),
    );
  });

  it("keeps real escapes and leaves clean scripts unchanged", () => {
    expect(unpackScript('Write-Host "a`tb`n"', "powershell").text).toBe('Write-Host "a`tb`n"');
    expect(unpackScript("console.log(1 + 2);", "javascript")).toMatchObject({ text: "console.log(1 + 2);", applied: [] });
  });
});
