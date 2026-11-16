import { useRef } from "react";
import { useThreeScene } from "./ccHooks";
import { SEV_HEX, SEV_ORDER } from "./ccConstants";

/**
 * 3D platform of stacked severity towers, one per finding type.
 * Heights use a log scale so one huge category doesn't flatten the rest;
 * the exact counts are in the labels.
 */
export default function SeverityTowers({ groups = [] }) {
  const mountRef = useRef(null);
  const labelRefs = useRef([]);
  const dataKey = groups.map((g) => `${g.key}:${SEV_ORDER.map((s) => g.sev[s] || 0).join(",")}`).join("|");

  useThreeScene(
    mountRef,
    ({ scene, camera, THREE }) => {
      camera.position.set(0, 6.2, 13.5);
      camera.lookAt(0, 1.4, 0);

      scene.add(new THREE.AmbientLight(0xa9c8ff, 0.75));
      const sun = new THREE.DirectionalLight(0xffffff, 1.1);
      sun.position.set(4, 8, 6);
      scene.add(sun);

      const world = new THREE.Group();
      scene.add(world);

      // Platform: disc plus glowing rings.
      const disc = new THREE.Mesh(
        new THREE.CylinderGeometry(5.4, 5.6, 0.18, 96),
        new THREE.MeshStandardMaterial({ color: 0x0b1a33, metalness: 0.4, roughness: 0.5 }),
      );
      disc.position.y = -0.09;
      world.add(disc);
      [5.5, 4.2, 2.9].forEach((radius, index) => {
        const glowRing = new THREE.Mesh(
          new THREE.TorusGeometry(radius, index === 0 ? 0.04 : 0.018, 8, 160),
          new THREE.MeshBasicMaterial({ color: index === 0 ? 0x5ce1ff : 0x2e7bff, transparent: true, opacity: index === 0 ? 0.9 : 0.5 }),
        );
        glowRing.rotation.x = Math.PI / 2;
        glowRing.position.y = 0.02;
        world.add(glowRing);
      });

      const n = Math.max(groups.length, 1);
      // Log heights, normalised so the tallest tower always fits the frame.
      const rawHeight = (count) => Math.log2(count + 1);
      const tallest = Math.max(
        1,
        ...groups.map((g) => SEV_ORDER.reduce((sum, sev) => sum + rawHeight(g.sev[sev] || 0), 0)),
      );
      const unit = 3.4 / tallest;
      const spacing = 2.3;
      const towers = groups.map((group, index) => {
        const x = (index - (n - 1) / 2) * spacing;
        const tower = new THREE.Group();
        tower.position.set(x, 0, 0);
        let y = 0;
        const segments = [];
        SEV_ORDER.forEach((sev) => {
          const count = group.sev[sev] || 0;
          if (!count) return;
          const h = Math.max(rawHeight(count) * unit, 0.12);
          const mesh = new THREE.Mesh(
            new THREE.BoxGeometry(1.05, h, 1.05),
            new THREE.MeshStandardMaterial({
              color: SEV_HEX[sev],
              emissive: SEV_HEX[sev],
              emissiveIntensity: 0.35,
              metalness: 0.2,
              roughness: 0.35,
              transparent: true,
              opacity: 0.92,
            }),
          );
          mesh.position.y = y + h / 2;
          mesh.userData.targetY = y + h / 2;
          mesh.scale.y = 0.001;
          tower.add(mesh);
          segments.push(mesh);
          y += h + 0.04;
        });
        // Base pad.
        const pad = new THREE.Mesh(
          new THREE.CylinderGeometry(0.95, 0.95, 0.04, 40),
          new THREE.MeshBasicMaterial({ color: 0x5ce1ff, transparent: true, opacity: 0.35 }),
        );
        pad.position.y = 0.02;
        tower.add(pad);
        world.add(tower);
        return { tower, segments, top: y };
      });

      const projected = new THREE.Vector3();
      return {
        update(t, dt, size) {
          world.rotation.y = Math.sin(t * 0.18) * 0.45;
          // Grow-in animation.
          towers.forEach(({ segments }) => {
            segments.forEach((mesh) => {
              mesh.scale.y += (1 - mesh.scale.y) * Math.min(1, dt * 3);
              mesh.position.y = mesh.userData.targetY * mesh.scale.y;
            });
          });
          // Keep HTML labels above each tower.
          towers.forEach(({ tower, top }, index) => {
            const el = labelRefs.current[index];
            if (!el) return;
            tower.getWorldPosition(projected);
            projected.y += top + 0.5;
            projected.project(camera);
            const x = Math.min(size.width - 40, Math.max(40, (projected.x * 0.5 + 0.5) * size.width));
            const yPx = Math.max(44, (-projected.y * 0.5 + 0.5) * size.height);
            el.style.transform = `translate(-50%, -100%) translate(${x}px, ${yPx}px)`;
          });
        },
      };
    },
    [dataKey],
  );

  return (
    <div className="cc-towers">
      <div ref={mountRef} className="cc-towers__canvas" />
      {groups.map((group, index) => (
        <div
          key={group.key}
          ref={(el) => { labelRefs.current[index] = el; }}
          className="cc-towers__label"
        >
          <strong>{group.total}</strong>
          <span>{group.label}</span>
        </div>
      ))}
      <ul className="cc-legend" aria-label="Severity colors">
        {SEV_ORDER.map((sev) => (
          <li key={sev}><span className={`cc-swatch cc-swatch--${sev}`} />{sev}</li>
        ))}
      </ul>
      <table className="cc-sr">
        <caption>Open issues by type and severity</caption>
        <thead><tr><th>Type</th>{SEV_ORDER.map((s) => <th key={s}>{s}</th>)}</tr></thead>
        <tbody>
          {groups.map((g) => (
            <tr key={g.key}><th>{g.label}</th>{SEV_ORDER.map((s) => <td key={s}>{g.sev[s] || 0}</td>)}</tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
