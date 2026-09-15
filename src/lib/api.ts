import {
  type DemoResult,
  type Evaluation,
  type ScenarioId,
  fallbackEvaluation,
  fallbackResult,
} from '@/lib/demo';

/**
 * Public research build.
 *
 * The prototype is deliberately self-contained: scenarios and evaluation
 * fixtures run locally in the browser, so the UI makes no authenticated or
 * organization-specific network requests.
 */
export async function runScenario(id: ScenarioId): Promise<{
  result: DemoResult;
  source: 'local-engine';
}> {
  return { result: fallbackResult(id), source: 'local-engine' };
}

export async function loadEvaluation(): Promise<Evaluation> {
  return fallbackEvaluation;
}
