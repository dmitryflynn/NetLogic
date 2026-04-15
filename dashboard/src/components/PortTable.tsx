interface Port {
  port:     number
  proto?:   string
  state:    string
  service:  string
  version?: string
  banner?:  string
}

export default function PortTable({ ports }: { ports: Port[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-[11px] border-collapse">
        <thead>
          <tr className="text-left text-text-dim border-b border-border">
            <th className="pb-2 pr-4 font-medium">Port</th>
            <th className="pb-2 pr-4 font-medium">Proto</th>
            <th className="pb-2 pr-4 font-medium">State</th>
            <th className="pb-2 pr-4 font-medium">Service</th>
            <th className="pb-2 font-medium">Version / Banner</th>
          </tr>
        </thead>
        <tbody>
          {ports.map((p) => (
            <tr key={`${p.port}-${p.proto}`} className="border-b border-border/40 hover:bg-elevated/40 transition-colors">
              <td className="py-1.5 pr-4 font-mono text-low font-bold">{p.port}</td>
              <td className="py-1.5 pr-4 text-text-dim uppercase">{p.proto ?? 'tcp'}</td>
              <td className="py-1.5 pr-4">
                <span className={p.state === 'open' ? 'text-low' : 'text-text-dim'}>
                  {p.state}
                </span>
              </td>
              <td className="py-1.5 pr-4 text-text">{p.service || '—'}</td>
              <td className="py-1.5 text-text-dim truncate max-w-xs">
                {p.version || p.banner || '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
