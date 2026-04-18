import { TargetGroupInput, TargetInput } from '../api/client';

export interface TargetGroupFormValue extends TargetGroupInput {
  targets?: TargetInput[];
}

export function emptyTargetGroupForm(): TargetGroupFormValue {
  return {
    name: '',
    protocol: 'http',
    verify_tls: true,
    algorithm: 'round_robin',
    health_check_enabled: false,
    health_check_path: '/',
    health_check_method: 'GET',
    health_check_expect_status: '200',
    health_check_interval_seconds: 30,
    health_check_timeout_seconds: 5,
    health_check_fails_to_unhealthy: 2,
    health_check_passes_to_healthy: 2,
    targets: [],
  };
}
