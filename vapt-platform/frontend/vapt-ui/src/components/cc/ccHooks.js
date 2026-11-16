import { useEffect, useRef, useState } from "react";
import * as echarts from "echarts";
import * as THREE from "three";

export const prefersReducedMotion = () =>
  typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

/**
 * Mounts a three.js scene into `containerRef`.
 * `setup({ scene, camera, renderer, THREE })` builds the scene and returns
 * `{ update(t, dt), dispose() }`. Handles sizing, the render loop, tab visibility,
 * reduced motion and cleanup. `deps` re-create the scene when they change.
 */
export function useThreeScene(containerRef, setup, deps) {
  const setupRef = useRef(setup);
  setupRef.current = setup;

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return undefined;

    let renderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    } catch {
      container.dataset.webgl = "unavailable";
      return undefined;
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setClearColor(0x000000, 0);
    container.appendChild(renderer.domElement);
    renderer.domElement.setAttribute("aria-hidden", "true");

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 200);
    const handle = setupRef.current({ scene, camera, renderer, THREE }) || {};

    const resize = () => {
      const width = container.clientWidth || 1;
      const height = container.clientHeight || 1;
      renderer.setSize(width, height, false);
      renderer.domElement.style.width = "100%";
      renderer.domElement.style.height = "100%";
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
    };
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(container);

    const still = prefersReducedMotion();
    let frame = 0;
    let last = performance.now();
    const start = last;
    const loop = (now) => {
      const dt = Math.min((now - last) / 1000, 0.1);
      last = now;
      handle.update?.((now - start) / 1000, dt, { width: container.clientWidth, height: container.clientHeight });
      renderer.render(scene, camera);
      if (!still) frame = requestAnimationFrame(loop);
    };
    frame = requestAnimationFrame(loop);

    const onVisibility = () => {
      if (document.hidden) cancelAnimationFrame(frame);
      else if (!still) {
        last = performance.now();
        frame = requestAnimationFrame(loop);
      }
    };
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      cancelAnimationFrame(frame);
      document.removeEventListener("visibilitychange", onVisibility);
      observer.disconnect();
      handle.dispose?.();
      scene.traverse((object) => {
        object.geometry?.dispose?.();
        const materials = Array.isArray(object.material) ? object.material : [object.material];
        materials.forEach((material) => material?.dispose?.());
      });
      renderer.dispose();
      renderer.domElement.remove();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}

/** A minimal ECharts mount: init once, setOption on change, resize with the box. */
export function useEChart(containerRef, option) {
  const chartRef = useRef(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return undefined;
    const chart = echarts.init(container, null, { renderer: "canvas" });
    chartRef.current = chart;
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(container);
    return () => {
      observer.disconnect();
      chart.dispose();
      chartRef.current = null;
    };
  }, [containerRef]);

  useEffect(() => {
    if (!chartRef.current || !option) return;
    const reduced = prefersReducedMotion();
    chartRef.current.setOption({ animation: !reduced, ...option }, { notMerge: false, lazyUpdate: true });
  }, [option]);
}

/** Counts smoothly from the previous value to `value` (instant with reduced motion). */
export function useAnimatedNumber(value, duration = 900) {
  const [display, setDisplay] = useState(value);
  const fromRef = useRef(value);

  useEffect(() => {
    const from = fromRef.current;
    const to = Number(value) || 0;
    let frame = 0;
    if (prefersReducedMotion() || from === to) {
      fromRef.current = to;
      frame = requestAnimationFrame(() => setDisplay(to));
      return () => cancelAnimationFrame(frame);
    }
    const start = performance.now();
    const step = (now) => {
      const p = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      setDisplay(Math.round(from + (to - from) * eased));
      if (p < 1) frame = requestAnimationFrame(step);
      else fromRef.current = to;
    };
    frame = requestAnimationFrame(step);
    return () => {
      cancelAnimationFrame(frame);
      fromRef.current = to;
    };
  }, [value, duration]);

  return display;
}
