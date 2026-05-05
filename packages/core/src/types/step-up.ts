import type {
  StepUpInputState,
  Phase1ErrorDetails,
  StepUpPreferredMethod,
  StepUpStatusObject,
} from './errors.js';

export const DEFAULT_STEP_UP_POLICY = {
  stepUpTokenTtlSeconds: 300,
  stepUpActionTtlSeconds: 600,
  stepUpReceiptTtlSeconds: 300,
  stepUpAttemptLimit: 5,
  stepUpResendCooldownSeconds: 60,
  stepUpMaxResends: 3,
} as const;

export interface StepUpAcceptableMethods {
  categories?: string[];
  methods?: string[];
}

export interface StepUpRequirement {
  step_up_token: string;
  expires_at: string;
  expires_at_unix: number;
  acceptable_methods: StepUpAcceptableMethods;
}

export interface StepUpNextAction {
  type: string;
  method: string;
  category?: string;
  action_id: string;
  expires_at: string;
  expires_at_unix?: number;
  payload: Record<string, unknown>;
}

export interface StepUpActionResponse {
  action_id: string;
  status: StepUpStatusObject;
  next_action?: StepUpNextAction;
  step_up_receipt?: string;
  step_up_receipt_expires_at?: string;
  step_up_receipt_expires_at_unix?: number;
}

export interface StepUpStartRequest {
  step_up_token: string;
  preferred_method?: StepUpPreferredMethod;
}

export interface StepUpCompleteRequest<Input = unknown> {
  method: string;
  input: Input;
}

export interface StepUpResendResponse extends StepUpActionResponse {
  next_action: StepUpNextAction;
}

export interface StepUpFailureBody {
  error: string;
  error_description?: string;
  error_details?: Phase1ErrorDetails;
  status?: StepUpStatusObject;
  input_state?: StepUpInputState;
  next_action?: StepUpNextAction;
  step_up?: StepUpRequirement;
}
