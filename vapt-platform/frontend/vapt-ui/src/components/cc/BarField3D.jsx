import { useRef, useState } from "react";
import { useThreeScene } from "./ccHooks";

/**
 * Generic 3D field of bars: one row per series (z), one column per category (x),
 * height = value on a log scale. Hover a bar to get `describe(row, col, value)` in the readout.
 *
 * rows:   [{ key, label, color }]  color is a hex number (0xff6b6b)
 * cols:   [label]
 * values: values[rowIndex][colIndex]
 */
export default function BarField3D({ rows = [], cols = [], values = [], describe, hint = "Hover a bar for exact counts", footer = null, caption = "" }) {
  const mountRef = useRef(null);
  const [hover, setHover] = useState(null);
  const dataKey = `${rows.map((r) => r.key).join(",")}|${cols.join(",")}|${values.map((v) => v.join(",")).join("|")}`;

  useThreeScene(
    mountRef,
    ({ scene, camera, renderer, THREE }) => {
      const n = Math.max(cols.length, 1);
      const depth = Math.max(rows.length, 1);
      const spacing = Math.min(2.4, 15 / n); // wider gaps when there are only a few columns
      const rowGap = Math.min(1.3, 9 / depth);
      const width = spacing * n;
      camera.position.set(0, 7.2 + depth * 0.15, 12.5 + depth * 0.25);
      camera.lookAt(0, 0.6, 0);

      scene.add(new THREE.AmbientLight(0xa9c8ff, 0.7));
      const sun = new THREE.DirectionalLight(0xffffff, 1.1);
      sun.position.set(-5, 9, 7);
      scene.add(sun);

      const world = new THREE.Group();
      scene.add(world);

      const floor = new THREE.Mesh(
        new THREE.BoxGeometry(width + 1.2, 0.08, depth * rowGap + 0.8),
        new THREE.MeshStandardMaterial({ color: 0x0b1a33, metalness: 0.4, roughness: 0.55 }),
      );
      floor.position.y = -0.04;
      world.add(floor);
      const grid = new THREE.GridHelper(Math.max(width + 1.2, depth * rowGap + 0.8), Math.max(4, Math.round(n)), 0x2e7bff, 0x173058);
      grid.position.y = 0.005;
      grid.material.transparent = true;
      grid.material.opacity = 0.45;
      world.add(grid);

      const max = Math.max(1, ...values.flat());
      const unit = 3.6 / Math.log2(max + 1);
      const bars = [];
      const geometry = new THREE.BoxGeometry(spacing * 0.72, 1, rowGap * 0.66);
      rows.forEach((row, r) => {
        const z = (r - (depth - 1) / 2) * rowGap;
        (values[r] || []).forEach((value, c) => {
          if (!value) return;
          const h = Math.max(0.08, Math.log2(value + 1) * unit);
          const mesh = new THREE.Mesh(
            geometry,
            new THREE.MeshStandardMaterial({
              color: row.color,
              emissive: row.color,
              emissiveIntensity: 0.3,
              metalness: 0.2,
              roughness: 0.35,
              transparent: true,
              opacity: 0.9,
            }),
          );
          mesh.position.set((c - (n - 1) / 2) * spacing, 0, z);
          mesh.scale.y = 0.001;
          mesh.userData = { h, delay: c * 0.05 + r * 0.08, r, c, value };
          world.add(mesh);
          bars.push(mesh);
        });
      });

      const raycaster = new THREE.Raycaster();
      const pointer = new THREE.Vector2();
      let pointerActive = false;
      let hovered = null;
      const el = renderer.domElement;
      const onMove = (event) => {
        const rect = el.getBoundingClientRect();
        pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
        pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
        pointerActive = true;
      };
      const onLeave = () => {
        pointerActive = false;
      };
      el.addEventListener("pointermove", onMove);
      el.addEventListener("pointerleave", onLeave);

      return {
        update(t) {
          world.rotation.y = -0.35 + Math.sin(t * 0.15) * 0.25;
          bars.forEach((mesh) => {
            const { h, delay } = mesh.userData;
            const p = Math.min(1, Math.max(0, (t - delay) * 1.6));
            const eased = 1 - Math.pow(1 - p, 3);
            mesh.scale.y = Math.max(0.001, h * eased);
            mesh.position.y = (h * eased) / 2;
          });
          let hit = null;
          if (pointerActive) {
            raycaster.setFromCamera(pointer, camera);
            hit = raycaster.intersectObjects(bars, false)[0]?.object || null;
          }
          if (hit !== hovered) {
            if (hovered) hovered.material.emissiveIntensity = 0.3;
            if (hit) hit.material.emissiveIntensity = 0.9;
            hovered = hit;
            setHover(hit ? { r: hit.userData.r, c: hit.userData.c, value: hit.userData.value } : null);
          }
        },
        dispose() {
          el.removeEventListener("pointermove", onMove);
          el.removeEventListener("pointerleave", onLeave);
          geometry.dispose();
        },
      };
    },
    [dataKey],
  );

  const hex = (n) => `#${n.toString(16).padStart(6, "0")}`;
  return (
    <div className="an-terrain">
      <div className="an-terrain__stage">
      <div ref={mountRef} className="an-terrain__canvas" />
      <div className="an-terrain__readout" aria-live="polite">
        {hover ? (
          <>
            <span className="cc-swatch" style={{ background: hex(rows[hover.r].color) }} />
            {describe ? describe(rows[hover.r], cols[hover.c], hover.value) : <><strong>{hover.value}</strong> {rows[hover.r].label} · {cols[hover.c]}</>}
          </>
        ) : (
          <span className="cc-muted">{hint}</span>
        )}
      </div>
      </div>
      {footer}
      <ul className="cc-legend" aria-label="Series colors">
        {rows.map((row) => (
          <li key={row.key}><span className="cc-swatch" style={{ background: hex(row.color) }} />{row.label}</li>
        ))}
      </ul>
      <div className="cc-sr"><table>
        <caption>{caption}</caption>
        <thead><tr><th>Series</th>{cols.map((c) => <th key={c}>{c}</th>)}</tr></thead>
        <tbody>
          {rows.map((row, r) => (
            <tr key={row.key}><th>{row.label}</th>{cols.map((c, i) => <td key={c}>{values[r]?.[i] || 0}</td>)}</tr>
          ))}
        </tbody>
      </table></div>
    </div>
  );
}
