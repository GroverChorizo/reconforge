import React, { useRef, useEffect } from "react";
import { Terminal } from "lucide-react";

export default function Console({ log, min, setMin }) {
  const ref = useRef(null);
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [log]);
  const last = log[log.length - 1];
  return (
    <section className={`console ${min ? "min" : ""}`}>
      <div className="chead">
        <div className="ct">
          <Terminal /> Activity Console
          {min
            ? <span className="cc">· {log.length} events · {last ? last.m : "idle"}</span>
            : <span className="cc">{log.length} events</span>}
        </div>
        <button className="cbtn" onClick={() => setMin(!min)}>{min ? "expand" : "minimize"}</button>
      </div>
      <div className="cstream" ref={ref}>
        {log.map((l, i) => (
          <div key={i} className={`cline ${l.k}`}>
            <span className="ts">[{l.t}]</span>
            <span className="src">{l.s}</span>
            <span className="msg">{l.m}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
