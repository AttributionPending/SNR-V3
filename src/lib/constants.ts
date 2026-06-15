// Shared display constants used across email preview components

export const TLP_BAND_COLORS: Record<string, string> = {
  CLEAR: 'bg-gray-200',
  GREEN: 'bg-green-600',
  AMBER: 'bg-yellow-500',
  'AMBER+STRICT': 'bg-orange-500',
  RED: 'bg-red-600',
};

export const SEVERITY_BAND: Record<string, string> = {
  Critical: 'bg-red-800 text-red-100',
  High: 'bg-red-700 text-red-100',
  Medium: 'bg-orange-700 text-orange-100',
  Low: 'bg-green-700 text-green-100',
  Informational: 'bg-blue-700 text-blue-100',
};
