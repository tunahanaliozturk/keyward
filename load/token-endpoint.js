// Load profile for the token endpoint.
//
// Run against a instance started with `docker compose up`:
//
//   k6 run load/token-endpoint.js
//   k6 run -e HOST=http://localhost:5100 -e DURATION=2m load/token-endpoint.js
//
// Only the client credentials grant is driven here, and that is deliberate rather than a shortcut. It is
// the grant that runs in a loop in production: a service asks for a token every few minutes, forever,
// while an interactive sign-in happens once a day and spends most of its time waiting for a person to
// type. Measuring the two together would produce a number that describes neither.
//
// k6 is AGPL-3.0 and runs as an external tool. Nothing in this repository links against it, so it does
// not appear in the dependency tree the licence audit walks.

import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

const host = __ENV.HOST || 'http://localhost:5100';
const duration = __ENV.DURATION || '60s';
const rate = Number(__ENV.RATE || 200);

const issuance = new Trend('token_issuance_ms', true);

export const options = {
  scenarios: {
    client_credentials: {
      executor: 'constant-arrival-rate',
      rate,
      timeUnit: '1s',
      duration,
      preAllocatedVUs: 40,
      maxVUs: 200,
    },
  },
  thresholds: {
    // A token request is a database write plus a signature. If the ninety-ninth percentile is above a
    // tenth of a second, something is queueing that should not be.
    'http_req_failed': ['rate<0.01'],
    'token_issuance_ms': ['p(50)<40', 'p(99)<100'],
  },
};

const body = {
  grant_type: 'client_credentials',
  client_id: 'keyward-demo-service',
  client_secret: 'ChangeMe!Service-Secret',
  scope: 'api',
};

export default function () {
  const response = http.post(`${host}/connect/token`, body, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  issuance.add(response.timings.duration);

  check(response, {
    'issued a token': (r) => r.status === 200 && r.json('access_token') !== undefined,
  });
}
