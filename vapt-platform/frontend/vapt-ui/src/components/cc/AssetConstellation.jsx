import { useRef } from "react";
import { useThreeScene } from "./ccHooks";
import { CRIT_HEX, ENV_ORDER, isExternal, normalizeCrit, normalizeEnv } from "./ccConstants";

/**
 * 3D constellation of targets: one ring per environment (production innermost),
 * node size by risk score, colour by criticality; external targets float above the plane.
 */
export default function AssetConstellation({ assets = [] }) {
  const mountRef = useRef(null);
  const key = assets.map((a) => `${a.id}:${a.criticality}:${Math.round(a.risk_score || 0)}:${a.environment}:${isExternal(a)}`).join("|");

  useThreeScene(
    mountRef,
    ({ scene, camera, THREE }) => {
      scene.add(new THREE.AmbientLight(0x9fc4ff, 0.8));

      const world = new THREE.Group();
      scene.add(world);

      // Core and environment rings.
      const core = new THREE.Mesh(
        new THREE.IcosahedronGeometry(0.55, 1),
        new THREE.MeshBasicMaterial({ color: 0x5ce1ff, wireframe: true, transparent: true, opacity: 0.7 }),
      );
      world.add(core);

      // Each environment gets a band; crowded bands split into several lanes so nodes don't overlap.
      const used = ENV_ORDER.filter((env) => assets.some((a) => normalizeEnv(a.environment) === env));
      const PER_LANE = 16;
      const LANE_GAP = 0.75;
      const bands = {};
      let radius = 2.2;
      used.forEach((env, index) => {
        const count = assets.filter((a) => normalizeEnv(a.environment) === env).length;
        const lanes = Math.max(1, Math.ceil(count / PER_LANE));
        bands[env] = { start: radius, lanes };
        for (let lane = 0; lane < lanes; lane += 1) {
          const r = radius + lane * LANE_GAP;
          const ring = new THREE.Mesh(
            new THREE.TorusGeometry(r, lane === 0 ? 0.016 : 0.008, 6, 200),
            new THREE.MeshBasicMaterial({ color: index === 0 ? 0x5ce1ff : 0x2e7bff, transparent: true, opacity: lane === 0 ? 0.5 : 0.25 }),
          );
          ring.rotation.x = Math.PI / 2;
          world.add(ring);
        }
        radius += lanes * LANE_GAP + 0.9;
      });
      const outer = Math.max(3, radius);
      // Fit the camera to the outermost ring.
      camera.position.set(0, outer * 0.95 + 1.5, outer * 1.45 + 1.5);
      camera.lookAt(0, 0.3, 0);

      const nodes = [];
      used.forEach((env) => {
        const members = assets.filter((a) => normalizeEnv(a.environment) === env);
        const { start, lanes } = bands[env];
        const perLane = Math.ceil(members.length / lanes);
        members.forEach((asset, i) => {
          const lane = Math.floor(i / perLane);
          const inLane = Math.min(perLane, members.length - lane * perLane);
          const angle = ((i % perLane) / inLane) * Math.PI * 2 + lane * 0.35;
          const radius = start + lane * LANE_GAP;
          const risk = Math.max(0, Math.min(100, Number(asset.risk_score) || 0));
          const size = 0.09 + (risk / 100) * 0.22;
          const color = CRIT_HEX[normalizeCrit(asset.criticality)];
          const node = new THREE.Mesh(
            new THREE.SphereGeometry(size, 16, 16),
            new THREE.MeshBasicMaterial({ color }),
          );
          const halo = new THREE.Mesh(
            new THREE.SphereGeometry(size * 2.2, 16, 16),
            new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.15 }),
          );
          node.add(halo);
          const lift = isExternal(asset) ? 1.1 : 0;
          node.position.set(Math.cos(angle) * radius, lift, Math.sin(angle) * radius);
          world.add(node);
          if (lift) {
            // A thin beam marks externally exposed targets.
            const beam = new THREE.Mesh(
              new THREE.CylinderGeometry(0.01, 0.01, lift, 6),
              new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.5 }),
            );
            beam.position.set(node.position.x, lift / 2, node.position.z);
            world.add(beam);
          }
          nodes.push({ halo, phase: Math.random() * Math.PI * 2, hot: risk >= 70 });
        });
      });

      return {
        update(t, dt) {
          world.rotation.y += dt * 0.08;
          core.rotation.y += dt * 0.4;
          nodes.forEach((n) => {
            if (n.hot) n.halo.scale.setScalar(1 + Math.sin(t * 3 + n.phase) * 0.35);
          });
        },
      };
    },
    [key],
  );

  return <div ref={mountRef} className="ti-constellation" />;
}
