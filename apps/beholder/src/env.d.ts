declare module "*.txt" {
  const value: string;
  export default value;
}

interface BeholderEnv {
  DECISIONS: DurableObjectNamespace;
  BEHOLDER_MODEL: string;
  BEHOLDER_PROVIDER_URL: string;
  BEHOLDER_PROVIDER_KEY: string;
  BEHOLDER_TRACE_KEY: string;
}
