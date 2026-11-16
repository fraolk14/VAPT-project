import { useRef } from "react";
import { useAnimatedNumber, useThreeScene } from "./ccHooks";

const STATE_COLOR = { active: 0x5ce1ff, healthy: 0x3ddc97, down: 0x5b6b7d };

/**
 * Animated 3D "scan reactor": a glowing core, counter-rotating rings, and one orbiting
 * node per scanner engine. Rings spin faster while scans are running.
 */
export default function ReactorCore({ engines = [], running = 0, total = 0, label = "Open issues" }) {
  const mountRef = useRef(null);
  const shown = useAnimatedNumber(total);
  const engineKey = engines.map((e) => `${e.name}:${e.state}`).join("|");

  useThreeScene(
    mountRef,
    ({ scene, camera, THREE }) => {
      camera.position.set(0, 2.4, 9.5);
      camera.lookAt(0, 0, 0);

      scene.add(new THREE.AmbientLight(0x6fa8ff, 0.6));
      const key = new THREE.PointLight(0x5ce1ff, 30, 30);
      key.position.set(0, 3, 4);
      scene.add(key);

      const group = new THREE.Group();
      group.rotation.x = 0.35;
      scene.add(group);

      // Core: wireframe icosahedron around a soft glowing sphere.
      const core = new THREE.Mesh(
        new THREE.IcosahedronGeometry(1.15, 1),
        new THREE.MeshBasicMaterial({ color: 0x5ce1ff, wireframe: true, transparent: true, opacity: 0.55 }),
      );
      const glow = new THREE.Mesh(
        new THREE.SphereGeometry(0.85, 32, 32),
        new THREE.MeshBasicMaterial({ color: 0x1b6dff, transparent: true, opacity: 0.35 }),
      );
      group.add(core, glow);

      const ring = (radius, tube, color, opacity) =>
        new THREE.Mesh(
          new THREE.TorusGeometry(radius, tube, 12, 160),
          new THREE.MeshBasicMaterial({ color, transparent: true, opacity }),
        );
      const outer = ring(3.3, 0.025, 0x8fd6ff, 0.9);
      outer.rotation.x = Math.PI / 2;
      const middle = ring(2.55, 0.012, 0x5ce1ff, 0.6);
      middle.rotation.x = Math.PI / 2;
      group.add(outer, middle);

      // Dashed arc segments on the middle ring.
      const arcs = new THREE.Group();
      for (let i = 0; i < 6; i += 1) {
        const arc = new THREE.Mesh(
          new THREE.TorusGeometry(2.85, 0.05, 8, 40, Math.PI / 6),
          new THREE.MeshBasicMaterial({ color: i % 2 ? 0x3ddc97 : 0x5ce1ff, transparent: true, opacity: 0.85 }),
        );
        arc.rotation.x = Math.PI / 2;
        arc.rotation.z = (i / 6) * Math.PI * 2;
        arcs.add(arc);
      }
      group.add(arcs);

      // Engine nodes orbiting on the outer ring.
      const nodes = engines.map((engine, index) => {
        const color = STATE_COLOR[engine.state] ?? STATE_COLOR.down;
        const node = new THREE.Mesh(
          new THREE.SphereGeometry(0.17, 20, 20),
          new THREE.MeshBasicMaterial({ color }),
        );
        const halo = new THREE.Mesh(
          new THREE.SphereGeometry(0.34, 20, 20),
          new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.18 }),
        );
        node.add(halo);
        group.add(node);
        return { node, halo, phase: (index / Math.max(engines.length, 1)) * Math.PI * 2, state: engine.state };
      });

      // Particle field.
      const count = 420;
      const positions = new Float32Array(count * 3);
      for (let i = 0; i < count; i += 1) {
        const r = 3.6 + Math.random() * 3.2;
        const a = Math.random() * Math.PI * 2;
        positions[i * 3] = Math.cos(a) * r;
        positions[i * 3 + 1] = (Math.random() - 0.5) * 2.4;
        positions[i * 3 + 2] = Math.sin(a) * r;
      }
      const dust = new THREE.Points(
        new THREE.BufferGeometry().setAttribute("position", new THREE.BufferAttribute(positions, 3)),
        new THREE.PointsMaterial({ color: 0x6fb8ff, size: 0.035, transparent: true, opacity: 0.7 }),
      );
      group.add(dust);

      const speed = running > 0 ? 1.8 : 0.6;
      return {
        update(t, dt) {
          core.rotation.y += dt * 0.35 * speed;
          core.rotation.x += dt * 0.12 * speed;
          glow.scale.setScalar(1 + Math.sin(t * 2.2) * 0.06 * speed);
          middle.rotation.z -= dt * 0.25 * speed;
          arcs.rotation.z += dt * 0.5 * speed;
          dust.rotation.y += dt * 0.04 * speed;
          nodes.forEach((item) => {
            const angle = item.phase + t * 0.35 * speed;
            item.node.position.set(Math.cos(angle) * 3.3, 0, Math.sin(angle) * 3.3);
            const pulse = item.state === "active" ? 1 + Math.sin(t * 6) * 0.35 : 1;
            item.halo.scale.setScalar(pulse);
          });
        },
      };
    },
    [engineKey, running > 0],
  );

  return (
    <div className="cc-reactor">
      <div ref={mountRef} className="cc-reactor__canvas" />
      <div className="cc-reactor__center" aria-live="polite">
        <strong>{shown}</strong>
        <span>{label}</span>
      </div>
      <ul className="cc-reactor__legend" aria-label="Scanner engines">
        {engines.map((engine) => (
          <li key={engine.name}>
            <span className={`cc-dot cc-dot--${engine.state}`} />
            {engine.name}
            <em>{engine.state === "active" ? "scanning" : engine.state === "healthy" ? "ready" : "offline"}</em>
          </li>
        ))}
      </ul>
    </div>
  );
}
