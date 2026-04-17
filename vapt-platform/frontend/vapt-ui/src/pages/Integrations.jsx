import { useEffect, useState } from "react";

import api from "../api/client";

function StatusDot({ healthy }) {
  return <span className={`status-dot ${healthy ? "is-healthy" : "is-unhealthy"}`} />;
}

function integrationLabel(name) {
  if (name === "openvas") return "Network Engine";
  if (name === "zap") return "Web Engine";
  if (name === "mobsf") return "Mobile Engine";
  if (name === "misp") return "Threat Feed Engine";
  return name;
}

const emptyPluginForm = { name: "", plugin_type: "scanner", version: "1.0.0", entrypoint: "", capabilities: "" };
const emptyKeyForm = { name: "", role_scope: "analyst" };
const emptyHookForm = { name: "", provider: "github", project_name: "", target_url: "" };
const emptyRuleForm = { name: "", event_source: "siem", event_type: "suspicious_login", target_match: "", action: "queue_scan", tool: "openvas" };
const emptyAlertForm = { name: "", channel: "email", destination: "", min_severity: "high", scan_tool: "" };
const emptyEventForm = { source: "siem", event_type: "suspicious_login", target: "", severity: "high" };

export default function Integrations({ integrations, platformData, alertRules, alertEvents, setAlerts }) {
  const [plugins, setPlugins] = useState(platformData?.plugins || []);
  const [apiKeys, setApiKeys] = useState(platformData?.apiKeys || []);
  const [hooks, setHooks] = useState(platformData?.hooks || []);
  const [events, setEvents] = useState(platformData?.events || []);
  const [monitoringRules, setMonitoringRules] = useState(platformData?.monitoringRules || []);
  const [monitoringEvents, setMonitoringEvents] = useState(platformData?.monitoringEvents || []);
  const [localAlertRules, setLocalAlertRules] = useState(alertRules || []);
  const [localAlertEvents, setLocalAlertEvents] = useState(alertEvents || []);
  const [pluginForm, setPluginForm] = useState(emptyPluginForm);
  const [keyForm, setKeyForm] = useState(emptyKeyForm);
  const [hookForm, setHookForm] = useState(emptyHookForm);
  const [ruleForm, setRuleForm] = useState(emptyRuleForm);
  const [alertForm, setAlertForm] = useState(emptyAlertForm);
  const [eventForm, setEventForm] = useState(emptyEventForm);
  const [createdSecrets, setCreatedSecrets] = useState({ apiKey: "", hook: "" });
  const [feedback, setFeedback] = useState("");
  const [feedbackType, setFeedbackType] = useState("idle");

  useEffect(() => setPlugins(platformData?.plugins || []), [platformData?.plugins]);
  useEffect(() => setApiKeys(platformData?.apiKeys || []), [platformData?.apiKeys]);
  useEffect(() => setHooks(platformData?.hooks || []), [platformData?.hooks]);
  useEffect(() => setEvents(platformData?.events || []), [platformData?.events]);
  useEffect(() => setMonitoringRules(platformData?.monitoringRules || []), [platformData?.monitoringRules]);
  useEffect(() => setMonitoringEvents(platformData?.monitoringEvents || []), [platformData?.monitoringEvents]);
  useEffect(() => setLocalAlertRules(alertRules || []), [alertRules]);
  useEffect(() => setLocalAlertEvents(alertEvents || []), [alertEvents]);

  const createPlugin = async (event) => {
    event.preventDefault();
    try {
      const response = await api.post("/platform/plugins", {
        ...pluginForm,
        capabilities: pluginForm.capabilities.split(",").map((item) => item.trim()).filter(Boolean),
        config: {},
      });
      setPlugins((current) => [response.data, ...current]);
      setPluginForm(emptyPluginForm);
      setFeedbackType("success");
      setFeedback("Plugin registered successfully.");
    } catch (error) {
      setFeedbackType("error");
      setFeedback(error?.response?.data?.detail || "Unable to register the plugin right now.");
    }
  };

  const togglePlugin = async (pluginId) => {
    try {
      const response = await api.post(`/platform/plugins/${pluginId}/toggle`);
      setPlugins((current) => current.map((item) => (item.id === pluginId ? response.data : item)));
    } catch {
      setFeedbackType("error");
      setFeedback("Unable to update plugin state.");
    }
  };

  const createApiKey = async (event) => {
    event.preventDefault();
    try {
      const response = await api.post("/platform/api-keys", keyForm);
      setApiKeys((current) => [response.data, ...current]);
      setCreatedSecrets((current) => ({ ...current, apiKey: response.data.secret }));
      setKeyForm(emptyKeyForm);
      setFeedbackType("success");
      setFeedback("API key created. Copy the secret now.");
    } catch (error) {
      setFeedbackType("error");
      setFeedback(error?.response?.data?.detail || "Unable to create the API key right now.");
    }
  };

  const toggleApiKey = async (keyId) => {
    try {
      const response = await api.post(`/platform/api-keys/${keyId}/toggle`);
      setApiKeys((current) => current.map((item) => (item.id === keyId ? response.data : item)));
    } catch {
      setFeedbackType("error");
      setFeedback("Unable to update API key state.");
    }
  };

  const createHook = async (event) => {
    event.preventDefault();
    try {
      const response = await api.post("/platform/devsecops/hooks", { ...hookForm, metadata_json: {} });
      setHooks((current) => [response.data, ...current]);
      setCreatedSecrets((current) => ({ ...current, hook: response.data.secret }));
      setHookForm(emptyHookForm);
      setFeedbackType("success");
      setFeedback("CI/CD hook created. Copy the secret now.");
    } catch (error) {
      setFeedbackType("error");
      setFeedback(error?.response?.data?.detail || "Unable to create the hook right now.");
    }
  };

  const toggleHook = async (hookId) => {
    try {
      const response = await api.post(`/platform/devsecops/hooks/${hookId}/toggle`);
      setHooks((current) => current.map((item) => (item.id === hookId ? response.data : item)));
    } catch {
      setFeedbackType("error");
      setFeedback("Unable to update hook state.");
    }
  };

  const createMonitoringRule = async (event) => {
    event.preventDefault();
    try {
      const response = await api.post("/operations/monitoring/rules", { ...ruleForm, metadata_json: {} });
      setMonitoringRules((current) => [response.data, ...current]);
      setRuleForm(emptyRuleForm);
      setFeedbackType("success");
      setFeedback("Monitoring rule created.");
    } catch (error) {
      setFeedbackType("error");
      setFeedback(error?.response?.data?.detail || "Unable to create the monitoring rule right now.");
    }
  };

  const toggleMonitoringRule = async (ruleId) => {
    try {
      const response = await api.post(`/operations/monitoring/rules/${ruleId}/toggle`);
      setMonitoringRules((current) => current.map((item) => (item.id === ruleId ? response.data : item)));
    } catch {
      setFeedbackType("error");
      setFeedback("Unable to update monitoring rule state.");
    }
  };

  const createAlertRule = async (event) => {
    event.preventDefault();
    try {
      const response = await api.post("/alerts/rules", {
        ...alertForm,
        scan_tool: alertForm.scan_tool || null,
        metadata_json: {},
      });
      const nextRules = [response.data, ...localAlertRules];
      setLocalAlertRules(nextRules);
      setAlerts?.((current) => ({ ...current, rules: nextRules, events: current.events || [] }));
      setAlertForm(emptyAlertForm);
      setFeedbackType("success");
      setFeedback("Alert rule created.");
    } catch (error) {
      setFeedbackType("error");
      setFeedback(error?.response?.data?.detail || "Unable to create the alert rule right now.");
    }
  };

  const toggleAlertRule = async (ruleId) => {
    try {
      const response = await api.post(`/alerts/rules/${ruleId}/toggle`);
      const nextRules = localAlertRules.map((item) => (item.id === ruleId ? response.data : item));
      setLocalAlertRules(nextRules);
      setAlerts?.((current) => ({ ...current, rules: nextRules, events: current.events || [] }));
    } catch {
      setFeedbackType("error");
      setFeedback("Unable to update alert rule state.");
    }
  };

  const simulateMonitoringEvent = async (event) => {
    event.preventDefault();
    try {
      const response = await api.post("/operations/monitoring/events", {
        ...eventForm,
        payload: { simulated: true, runbook: "integrations-console" },
      });
      setMonitoringEvents((current) => [response.data, ...current]);
      setEventForm(emptyEventForm);
      setFeedbackType("success");
      setFeedback("Monitoring event simulated successfully.");
    } catch (error) {
      setFeedbackType("error");
      setFeedback(error?.response?.data?.detail || "Unable to simulate the monitoring event right now.");
    }
  };

  const testAlertRule = async (ruleId) => {
    try {
      const response = await api.post(`/alerts/rules/${ruleId}/test`);
      const nextEvents = [response.data.event, ...localAlertEvents];
      setLocalAlertEvents(nextEvents);
      setAlerts?.((current) => ({ ...current, rules: current.rules || [], events: nextEvents }));
      setFeedbackType("success");
      setFeedback(`Alert validation sent for ${response.data.rule.name}.`);
    } catch (error) {
      setFeedbackType("error");
      setFeedback(error?.response?.data?.detail || "Unable to validate the alert route right now.");
    }
  };

  const retryAlertEvent = async (eventId) => {
    try {
      const response = await api.post(`/alerts/events/${eventId}/retry`);
      const nextEvents = localAlertEvents.map((item) => (item.id === eventId ? response.data : item));
      setLocalAlertEvents(nextEvents);
      setAlerts?.((current) => ({ ...current, rules: current.rules || [], events: nextEvents }));
      setFeedbackType(response.data.status === "sent" ? "success" : "error");
      setFeedback(response.data.response_message || "Alert delivery retry completed.");
    } catch (error) {
      setFeedbackType("error");
      setFeedback(error?.response?.data?.detail || "Unable to retry this alert event.");
    }
  };

  return (
    <section className="section-grid">
      <section className="panel panel--metrics">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Control plane connectivity</p>
            <h2>Integrations</h2>
          </div>
        </div>
        <div className="integration-list">
          {Object.entries(integrations).map(([name, value]) => (
            <div key={name} className="integration-item">
              <div>
                <strong>{integrationLabel(name)}</strong>
                <p>{value.url}</p>
                {value.detail ? <p>{value.detail}</p> : null}
              </div>
              <div className="integration-item__status">
                <StatusDot healthy={value.healthy} />
                <span>{value.healthy ? "Healthy" : "Unavailable"}</span>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <div className="panel__header"><div><p className="eyebrow">Plugin system</p><h2>Register plugin</h2></div></div>
        <form className="form-grid" onSubmit={createPlugin}>
          <input className="scan-input" placeholder="Plugin name" value={pluginForm.name} onChange={(event) => setPluginForm((current) => ({ ...current, name: event.target.value }))} />
          <select className="scan-select" value={pluginForm.plugin_type} onChange={(event) => setPluginForm((current) => ({ ...current, plugin_type: event.target.value }))}>
            <option value="scanner">Scanner</option><option value="connector">Connector</option><option value="enricher">Enricher</option>
          </select>
          <input className="scan-input" placeholder="Version" value={pluginForm.version} onChange={(event) => setPluginForm((current) => ({ ...current, version: event.target.value }))} />
          <input className="scan-input" placeholder="Entrypoint" value={pluginForm.entrypoint} onChange={(event) => setPluginForm((current) => ({ ...current, entrypoint: event.target.value }))} />
          <input className="scan-input" placeholder="Capabilities (comma separated)" value={pluginForm.capabilities} onChange={(event) => setPluginForm((current) => ({ ...current, capabilities: event.target.value }))} />
          <button type="submit" className="scan-action scan-action--resume">Register Plugin</button>
        </form>
        <div className="coverage-list">
          {plugins.map((plugin) => (
            <div className="coverage-row" key={plugin.id}>
              <span>{plugin.name} ({plugin.plugin_type})</span>
              <strong>{plugin.enabled ? plugin.version : "disabled"} <button type="button" className="scan-action" onClick={() => togglePlugin(plugin.id)}>{plugin.enabled ? "Disable" : "Enable"}</button></strong>
            </div>
          ))}
          {!plugins.length ? <p className="empty-copy">No custom plugins have been registered yet.</p> : null}
        </div>
      </section>

      <section className="panel">
        <div className="panel__header"><div><p className="eyebrow">Public API</p><h2>API keys</h2></div></div>
        <form className="form-grid" onSubmit={createApiKey}>
          <input className="scan-input" placeholder="Key name" value={keyForm.name} onChange={(event) => setKeyForm((current) => ({ ...current, name: event.target.value }))} />
          <select className="scan-select" value={keyForm.role_scope} onChange={(event) => setKeyForm((current) => ({ ...current, role_scope: event.target.value }))}>
            <option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Admin</option>
          </select>
          <button type="submit" className="scan-action scan-action--resume">Create API Key</button>
        </form>
        {createdSecrets.apiKey ? <p className="panel-note">New API secret: <code>{createdSecrets.apiKey}</code></p> : null}
        <div className="coverage-list">
          {apiKeys.map((key) => (
            <div className="coverage-row" key={key.id}>
              <span>{key.name} ({key.role_scope})</span>
              <strong>{key.enabled ? key.key_prefix : "disabled"} <button type="button" className="scan-action" onClick={() => toggleApiKey(key.id)}>{key.enabled ? "Disable" : "Enable"}</button></strong>
            </div>
          ))}
          {!apiKeys.length ? <p className="empty-copy">No scoped API keys are registered yet.</p> : null}
        </div>
      </section>

      <section className="panel">
        <div className="panel__header"><div><p className="eyebrow">Pipeline integrations</p><h2>CI/CD hooks</h2></div></div>
        <form className="form-grid" onSubmit={createHook}>
          <input className="scan-input" placeholder="Hook name" value={hookForm.name} onChange={(event) => setHookForm((current) => ({ ...current, name: event.target.value }))} />
          <select className="scan-select" value={hookForm.provider} onChange={(event) => setHookForm((current) => ({ ...current, provider: event.target.value }))}>
            <option value="github">GitHub</option><option value="gitlab">GitLab</option><option value="jenkins">Jenkins</option>
          </select>
          <input className="scan-input" placeholder="Project name" value={hookForm.project_name} onChange={(event) => setHookForm((current) => ({ ...current, project_name: event.target.value }))} />
          <input className="scan-input" placeholder="Target URL" value={hookForm.target_url} onChange={(event) => setHookForm((current) => ({ ...current, target_url: event.target.value }))} />
          <button type="submit" className="scan-action scan-action--resume">Create Hook</button>
        </form>
        {createdSecrets.hook ? <p className="panel-note">New hook secret: <code>{createdSecrets.hook}</code></p> : null}
        {feedback ? <p className={`scan-feedback scan-feedback--${feedbackType}`}>{feedback}</p> : null}
        <div className="coverage-list">
          {hooks.map((hook) => (
            <div className="coverage-row" key={hook.id}>
              <span>{hook.project_name} ({hook.provider})</span>
              <strong>{hook.enabled ? `token •••${hook.secret_hint}` : "disabled"} <button type="button" className="scan-action" onClick={() => toggleHook(hook.id)}>{hook.enabled ? "Disable" : "Enable"}</button></strong>
            </div>
          ))}
          {!hooks.length ? <p className="empty-copy">No CI/CD hooks have been provisioned yet.</p> : null}
        </div>
      </section>

      <section className="panel">
        <div className="panel__header"><div><p className="eyebrow">Continuous monitoring</p><h2>Monitoring rules</h2></div></div>
        <form className="form-grid" onSubmit={createMonitoringRule}>
          <input className="scan-input" placeholder="Rule name" value={ruleForm.name} onChange={(event) => setRuleForm((current) => ({ ...current, name: event.target.value }))} />
          <input className="scan-input" placeholder="Event source" value={ruleForm.event_source} onChange={(event) => setRuleForm((current) => ({ ...current, event_source: event.target.value }))} />
          <input className="scan-input" placeholder="Event type" value={ruleForm.event_type} onChange={(event) => setRuleForm((current) => ({ ...current, event_type: event.target.value }))} />
          <input className="scan-input" placeholder="Target match (optional)" value={ruleForm.target_match} onChange={(event) => setRuleForm((current) => ({ ...current, target_match: event.target.value }))} />
          <select className="scan-select" value={ruleForm.tool} onChange={(event) => setRuleForm((current) => ({ ...current, tool: event.target.value }))}>
            <option value="openvas">Network Engine</option><option value="zap">Web Engine</option><option value="mobsf">Mobile Engine</option>
          </select>
          <button type="submit" className="scan-action scan-action--resume">Create Rule</button>
        </form>
        <div className="coverage-list">
          {monitoringRules.map((rule) => (
            <div className="coverage-row" key={rule.id}>
              <span>{rule.name}<p>{rule.event_source} / {rule.event_type}</p></span>
              <strong>{rule.enabled ? rule.tool : "disabled"} <button type="button" className="scan-action" onClick={() => toggleMonitoringRule(rule.id)}>{rule.enabled ? "Disable" : "Enable"}</button></strong>
            </div>
          ))}
          {!monitoringRules.length ? <p className="empty-copy">No event-driven monitoring rules are configured yet.</p> : null}
        </div>
        <form className="form-grid" onSubmit={simulateMonitoringEvent} style={{ marginTop: "14px" }}>
          <input className="scan-input" placeholder="Target to simulate" value={eventForm.target} onChange={(event) => setEventForm((current) => ({ ...current, target: event.target.value }))} />
          <select className="scan-select" value={eventForm.source} onChange={(event) => setEventForm((current) => ({ ...current, source: event.target.value }))}>
            <option value="siem">SIEM</option><option value="edr">EDR</option><option value="firewall">Firewall</option>
          </select>
          <input className="scan-input" placeholder="Event type" value={eventForm.event_type} onChange={(event) => setEventForm((current) => ({ ...current, event_type: event.target.value }))} />
          <select className="scan-select" value={eventForm.severity} onChange={(event) => setEventForm((current) => ({ ...current, severity: event.target.value }))}>
            <option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
          </select>
          <button type="submit" className="scan-action">Simulate Event</button>
        </form>
      </section>

      <section className="panel">
        <div className="panel__header"><div><p className="eyebrow">Alerting</p><h2>Alert rules</h2></div></div>
        <form className="form-grid" onSubmit={createAlertRule}>
          <input className="scan-input" placeholder="Alert name" value={alertForm.name} onChange={(event) => setAlertForm((current) => ({ ...current, name: event.target.value }))} />
          <select className="scan-select" value={alertForm.channel} onChange={(event) => setAlertForm((current) => ({ ...current, channel: event.target.value }))}>
            <option value="email">Email</option><option value="webhook">Webhook</option>
          </select>
          <input className="scan-input" placeholder="Destination" value={alertForm.destination} onChange={(event) => setAlertForm((current) => ({ ...current, destination: event.target.value }))} />
          <select className="scan-select" value={alertForm.min_severity} onChange={(event) => setAlertForm((current) => ({ ...current, min_severity: event.target.value }))}>
            <option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
          </select>
          <select className="scan-select" value={alertForm.scan_tool} onChange={(event) => setAlertForm((current) => ({ ...current, scan_tool: event.target.value }))}>
            <option value="">All engines</option><option value="openvas">Network Engine</option><option value="zap">Web Engine</option><option value="mobsf">Mobile Engine</option>
          </select>
          <button type="submit" className="scan-action scan-action--resume">Create Alert</button>
        </form>
        <div className="coverage-list">
          {localAlertRules.map((rule) => (
            <div className="coverage-row" key={rule.id}>
              <span>{rule.name}<p>{rule.channel} → {rule.destination}</p></span>
              <strong>
                {rule.enabled ? rule.min_severity : "disabled"}{" "}
                <button type="button" className="scan-action" onClick={() => toggleAlertRule(rule.id)}>{rule.enabled ? "Disable" : "Enable"}</button>{" "}
                <button type="button" className="scan-action" onClick={() => testAlertRule(rule.id)}>Test</button>
              </strong>
            </div>
          ))}
          {!localAlertRules.length ? <p className="empty-copy">No alert rules exist yet.</p> : null}
        </div>
      </section>

      <section className="panel panel--metrics">
        <div className="panel__header"><div><p className="eyebrow">Pipeline and event activity</p><h2>Recent events</h2></div></div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Stream</th><th>Event</th><th>Status</th><th>Created</th><th>Action</th>
              </tr>
            </thead>
            <tbody>
              {events.slice(0, 6).map((event) => (
                <tr key={event.id}>
                  <td data-label="Stream">CI/CD</td>
                  <td data-label="Event"><strong>{event.event_type}</strong><p>{event.summary || event.provider}</p></td>
                  <td data-label="Status">{event.status}</td>
                  <td data-label="Created">{new Date(event.created_at).toLocaleString()}</td>
                  <td data-label="Action">-</td>
                </tr>
              ))}
              {monitoringEvents.slice(0, 6).map((event) => (
                <tr key={event.id}>
                  <td data-label="Stream">Monitoring</td>
                  <td data-label="Event"><strong>{event.event_type}</strong><p>{event.target}</p></td>
                  <td data-label="Status">{event.status}</td>
                  <td data-label="Created">{new Date(event.created_at).toLocaleString()}</td>
                  <td data-label="Action">-</td>
                </tr>
              ))}
              {localAlertEvents.slice(0, 6).map((event) => (
                <tr key={event.id}>
                  <td data-label="Stream">Alerts</td>
                  <td data-label="Event"><strong>{event.rule_name}</strong><p>{event.destination}</p></td>
                  <td data-label="Status">{event.status}<p>{event.response_message}</p></td>
                  <td data-label="Created">{new Date(event.created_at).toLocaleString()}</td>
                  <td data-label="Action">
                    {event.status !== "sent" ? (
                      <button type="button" className="scan-action scan-action--resume" onClick={() => retryAlertEvent(event.id)}>Retry</button>
                    ) : "-"}
                  </td>
                </tr>
              ))}
              {!events.length && !monitoringEvents.length && !localAlertEvents.length ? <tr><td colSpan="5"><p className="empty-copy">No integration events have been ingested yet.</p></td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
    </section>
  );
}
