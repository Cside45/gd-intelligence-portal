/** Shared warrant crime types and duration options (main + IA dossiers). */

const WARRANT_CRIMES = [
  { value: "breach_of_peace", label: "Breach of peace" },
  { value: "attempted_murder", label: "Attempted murder" },
  { value: "murder", label: "Murder" },
  { value: "terrorism", label: "Terrorism" },
  { value: "attack_gd_personnel", label: "Attack on GD personnel" },
  { value: "theft", label: "Theft" },
  { value: "possession_contraband_minor", label: "Possession of contraband (minor)" },
  { value: "possession_contraband_felony", label: "Possession of contraband (felony)" },
];

/** Milliseconds for each preset (from activation time). */
const WARRANT_DURATION_MS = {
  "1h": 60 * 60 * 1000,
  "3h": 3 * 60 * 60 * 1000,
  "6h": 6 * 60 * 60 * 1000,
  "1d": 24 * 60 * 60 * 1000,
  "2d": 2 * 24 * 60 * 60 * 1000,
  "3d": 3 * 24 * 60 * 60 * 1000,
  "5d": 5 * 24 * 60 * 60 * 1000,
};

const WARRANT_DURATION_OPTIONS = [
  { value: "1h", label: "1 hour" },
  { value: "3h", label: "3 hours" },
  { value: "6h", label: "6 hours" },
  { value: "1d", label: "1 day" },
  { value: "2d", label: "2 days" },
  { value: "3d", label: "3 days" },
  { value: "5d", label: "5 days" },
];

/** Warrant classification: AoS, EoS, or KoS. */
const WARRANT_CLASSIFICATIONS = [
  { value: "AoS", label: "AoS" },
  { value: "EoS", label: "EoS" },
  { value: "KoS", label: "KoS" },
];

function crimeLabel(value) {
  const row = WARRANT_CRIMES.find((c) => c.value === value);
  return row ? row.label : value || "";
}

function classificationLabel(value) {
  const row = WARRANT_CLASSIFICATIONS.find((c) => c.value === value);
  return row ? row.label : value || "";
}

function computeExpiryIso(durationKey) {
  const ms = WARRANT_DURATION_MS[durationKey];
  if (!ms) return null;
  return new Date(Date.now() + ms).toISOString();
}

function isWarrantPubliclyActive(row) {
  if (!row || row.warrant_status !== "active") return false;
  if (!row.warrant_expires_at) return false;
  const t = new Date(row.warrant_expires_at).getTime();
  return t > Date.now();
}

module.exports = {
  WARRANT_CRIMES,
  WARRANT_DURATION_OPTIONS,
  WARRANT_CLASSIFICATIONS,
  WARRANT_DURATION_MS,
  crimeLabel,
  classificationLabel,
  computeExpiryIso,
  isWarrantPubliclyActive,
};
