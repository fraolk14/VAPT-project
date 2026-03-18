export default function Card({ title, value, trend }) {
  return (
    <article className="metric-card">
      <p>{title}</p>
      <strong>{value}</strong>
      <span>{trend}</span>
    </article>
  );
}
