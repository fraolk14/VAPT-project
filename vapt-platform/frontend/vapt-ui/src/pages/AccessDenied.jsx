export default function AccessDenied({ title = "Access denied", message = "You do not have permission to view this area." }) {
  return (
    <section className="panel">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Role-based access control</p>
          <h2>{title}</h2>
        </div>
      </div>
      <p className="empty-copy">{message}</p>
    </section>
  );
}
