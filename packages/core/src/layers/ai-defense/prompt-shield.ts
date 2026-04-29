import type { PromptAnalysis } from './types';
import { RiskLevel } from '@resimantle/types';

/**
 * A single prompt injection detection rule.
 */
interface InjectionPattern {
  name: string;
  pattern: RegExp;
  weight: number; // 0.0 to 1.0 — contribution to the risk score
  description: string;
  category: string;
}

/**
 * Comprehensive prompt injection patterns.
 * These detect a wide range of known prompt injection techniques,
 * jailbreaks, role-hijacking attempts, and social engineering in prompts.
 */
const INJECTION_PATTERNS: InjectionPattern[] = [
  // ── Direct instruction override ─────────────────────────────────────────
  {
    name: 'IGNORE_PREVIOUS',
    pattern: /ignore\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|directives?|rules?|context)/i,
    weight: 0.9,
    description: 'Attempts to override system instructions',
    category: 'instruction-override',
  },
  {
    name: 'FORGET_INSTRUCTIONS',
    pattern: /forget\s+(?:all\s+)?(?:your|the|my|any)\s+(?:instructions?|rules?|guidelines?|restrictions?|constraints?)/i,
    weight: 0.9,
    description: 'Attempts to erase system prompt memory',
    category: 'instruction-override',
  },
  {
    name: 'NEW_INSTRUCTIONS',
    pattern: /(?:new|updated|real|actual|true|correct)\s+(?:instructions?|system\s*prompt|directives?)\s*[:=]/i,
    weight: 0.85,
    description: 'Attempts to inject replacement instructions',
    category: 'instruction-override',
  },

  // ── Role hijacking ──────────────────────────────────────────────────────
  {
    name: 'ROLE_PLAY',
    pattern: /(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you(?:'re| are))|roleplay\s+as|simulate\s+being|from\s+now\s+on\s+you\s+are)\s/i,
    weight: 0.7,
    description: 'Attempts to make the model assume a different role',
    category: 'role-hijack',
  },
  {
    name: 'DAN_JAILBREAK',
    pattern: /(?:DAN|do\s+anything\s+now|jailbreak(?:ed)?|uncensored|unfiltered|no\s+restrictions?|without\s+(?:any\s+)?(?:restrictions?|limits?|boundaries|guidelines))/i,
    weight: 0.95,
    description: 'Known jailbreak technique (DAN/uncensored mode)',
    category: 'role-hijack',
  },
  {
    name: 'DEVELOPER_MODE',
    pattern: /(?:developer\s+mode|god\s+mode|admin\s+mode|debug\s+mode|maintenance\s+mode|test\s+mode)\s*(?:enabled|activated|on)/i,
    weight: 0.85,
    description: 'Attempts to enable privileged execution modes',
    category: 'privilege-escalation',
  },

  // ── System prompt extraction ────────────────────────────────────────────
  {
    name: 'SYSTEM_PROMPT_LEAK',
    pattern: /(?:show|reveal|display|print|output|repeat|tell\s+me|what\s+(?:is|are))\s+(?:your|the)\s+(?:system\s+prompt|instructions?|initial\s+prompt|hidden\s+prompt|system\s+message|original\s+(?:prompt|instructions?))/i,
    weight: 0.8,
    description: 'Attempts to extract system prompt contents',
    category: 'prompt-exfiltration',
  },
  {
    name: 'PROMPT_VERBATIM',
    pattern: /(?:repeat|echo|output)\s+(?:everything|all|the\s+(?:text|content))\s+(?:above|before|from\s+the\s+(?:beginning|start))/i,
    weight: 0.75,
    description: 'Attempts to extract full conversation context',
    category: 'prompt-exfiltration',
  },

  // ── Encoding / obfuscation attacks ──────────────────────────────────────
  {
    name: 'BASE64_INJECTION',
    pattern: /(?:decode|execute|run|eval)\s+(?:this\s+)?base64\s*[:=]?\s*[A-Za-z0-9+/=]{20,}/i,
    weight: 0.8,
    description: 'Encoded payload injection via Base64',
    category: 'obfuscation',
  },
  {
    name: 'MARKDOWN_INJECTION',
    pattern: /!\[.*?\]\((?:https?:\/\/|data:)[^)]*\)/,
    weight: 0.5,
    description: 'Markdown image injection (potential data exfiltration)',
    category: 'exfiltration',
  },
  {
    name: 'UNICODE_SMUGGLING',
    pattern: /[\u200B-\u200F\u2028-\u202F\uFEFF\u00AD]/,
    weight: 0.6,
    description: 'Zero-width / invisible Unicode characters detected (potential smuggling)',
    category: 'obfuscation',
  },

  // ── Tool / function abuse ───────────────────────────────────────────────
  {
    name: 'TOOL_ABUSE',
    pattern: /(?:call|execute|invoke|use|run)\s+(?:the\s+)?(?:function|tool|api|command|shell|terminal|bash|cmd)\s/i,
    weight: 0.6,
    description: 'Attempts to invoke tools or system commands',
    category: 'tool-abuse',
  },
  {
    name: 'FILE_SYSTEM_ACCESS',
    pattern: /(?:read|write|delete|modify|create|access|open)\s+(?:the\s+)?(?:file|directory|folder|path)\s/i,
    weight: 0.5,
    description: 'Attempts to perform filesystem operations',
    category: 'filesystem-access',
  },
  {
    name: 'CODE_EXECUTION',
    pattern: /(?:execute|run|eval(?:uate)?)\s+(?:this\s+)?(?:code|script|command|program|python|javascript|bash|sql)\s*[:=`]/i,
    weight: 0.7,
    description: 'Attempts to execute arbitrary code',
    category: 'code-execution',
  },

  // ── Social engineering ──────────────────────────────────────────────────
  {
    name: 'URGENCY_MANIPULATION',
    pattern: /(?:emergency|urgent|critical|immediately|right\s+now|this\s+is\s+(?:a\s+)?(?:life|death)|people\s+will\s+(?:die|be\s+hurt))/i,
    weight: 0.4,
    description: 'Social engineering via artificial urgency',
    category: 'social-engineering',
  },
  {
    name: 'AUTHORITY_CLAIM',
    pattern: /(?:I\s+am\s+(?:the\s+)?(?:CEO|admin|administrator|owner|developer|creator)|(?:OpenAI|Anthropic|Google)\s+(?:says|told|authorized|approved))/i,
    weight: 0.6,
    description: 'False authority claims to bypass restrictions',
    category: 'social-engineering',
  },

  // ── Delimiter / context boundary attacks ────────────────────────────────
  {
    name: 'DELIMITER_INJECTION',
    pattern: /(?:<\/?(?:system|user|assistant|human|ai|prompt|instruction)>|={3,}|---{3,}\s*(?:system|end|new))/i,
    weight: 0.7,
    description: 'Delimiter injection to alter message boundaries',
    category: 'obfuscation',
  },
  {
    name: 'XML_TAG_INJECTION',
    pattern: /<(?:system_prompt|instructions|context|hidden|secret|internal)[^>]*>/i,
    weight: 0.75,
    description: 'XML tag injection to hijack structured prompts',
    category: 'obfuscation',
  },

  // ── Data exfiltration ───────────────────────────────────────────────────
  {
    name: 'EXFIL_URL',
    pattern: /(?:send|post|transmit|forward|leak|exfiltrate)\s+(?:.*?\s+)?(?:to|via)\s+(?:https?:\/\/|webhook)/i,
    weight: 0.8,
    description: 'Potential data exfiltration via HTTP request',
    category: 'exfiltration',
  },
  {
    name: 'SECRET_HARVEST',
    pattern: /(?:find|locate|list|dump|harvest|extract|enumerate)\s+(?:all\s+)?(?:secrets?|credentials?|tokens?|passwords?|keys?|ssh\s+keys|private\s+keys|database\s+urls?|webhooks?|environment\s+variables|\.env)/i,
    weight: 0.92,
    description: 'Attempts to harvest secrets and credentials at scale',
    category: 'secret-access',
  },
  {
    name: 'REPO_RECON',
    pattern: /(?:prioritize|rank|enumerate|map|scan|triage|focus\s+on)\s+(?:the\s+)?(?:repository|repo|codebase|files|routes|endpoints|attack\s+surface|auth|billing|admin|internal)/i,
    weight: 0.82,
    description: 'Repository reconnaissance aimed at high-value targets',
    category: 'reconnaissance',
  },
  {
    name: 'PATCH_TO_EXPLOIT',
    pattern: /(?:turn|convert|weaponize|adapt)\s+(?:a\s+)?(?:patch|commit|cve|diff|n-day)\s+(?:into|as)\s+(?:an\s+)?exploit/i,
    weight: 0.95,
    description: 'Attempts to convert known fixes into exploit guidance',
    category: 'exploit-development',
  },
  {
    name: 'STEALTH_EVASION',
    pattern: /(?:avoid\s+detection|stay\s+stealthy|disable\s+logging|hide\s+traces|evade\s+(?:audit|detection)|clean\s+up\s+(?:history|logs))/i,
    weight: 0.92,
    description: 'Explicit evasion and anti-forensics intent',
    category: 'stealth',
  },
  {
    name: 'PARALLEL_AGENTIC_SCANNING',
    pattern: /(?:run|launch|spawn)\s+(?:multiple|parallel|several)\s+(?:agents?|workers?|processes|scans)/i,
    weight: 0.78,
    description: 'Parallelized autonomous reconnaissance or exploitation',
    category: 'agentic-scaling',
  },
  {
    name: 'PRIVILEGE_CHAIN',
    pattern: /(?:chain|combine)\s+(?:multiple\s+)?(?:vulnerabilities|primitives|bugs|steps)\s+(?:to|for)\s+(?:gain\s+root|escalate\s+privileges|bypass\s+auth|reach\s+admin)/i,
    weight: 0.94,
    description: 'Privilege escalation or exploit chaining intent',
    category: 'privilege-escalation',
  },
];

/**
 * The Prompt Shield is the core AI defense component.
 * It analyzes prompts for injection patterns, jailbreak attempts,
 * role hijacking, encoding attacks, and social engineering.
 *
 * Scoring is probabilistic: each matched pattern contributes a weighted score,
 * and the final risk level is determined by the aggregate.
 */
export class PromptShield {
  private customPatterns: InjectionPattern[] = [];

  /**
   * Register additional custom patterns for domain-specific threats.
   */
  addPattern(pattern: InjectionPattern): void {
    this.customPatterns.push(pattern);
  }

  /**
   * Analyzes a prompt string for potential injection attacks.
   *
   * Returns a detailed analysis including:
   * - Whether the prompt is considered safe
   * - The aggregated injection risk level
   * - A list of all matched flags with descriptions
   * - A numeric confidence score (0.0 = clean, 1.0 = definitely malicious)
   */
  async analyze(prompt: string): Promise<PromptAnalysis> {
    const allPatterns = [...INJECTION_PATTERNS, ...this.customPatterns];
    const flags: string[] = [];
    const categories = new Set<string>();
    let totalWeight = 0;
    let maxWeight = 0;

    for (const rule of allPatterns) {
      if (rule.pattern.test(prompt)) {
        flags.push(`[${rule.name}] ${rule.description}`);
        categories.add(rule.category);
        totalWeight += rule.weight;
        maxWeight = Math.max(maxWeight, rule.weight);
      }
    }

    // Normalize the score: diminishing returns for multiple matches
    // but a single very high-weight match can push it high alone
    const aggregateScore = Math.min(1.0, (totalWeight * 0.4) + (maxWeight * 0.6));
    const injectionRisk = scoreToRisk(aggregateScore);
    const isSafe = aggregateScore < 0.3;

    return {
      isSafe,
      injectionRisk,
      flags,
      categories: Array.from(categories).sort(),
      score: Math.round(aggregateScore * 100) / 100,
      patternsMatched: flags.length,
    };
  }
}

/**
 * Maps a numeric score (0.0-1.0) to a RiskLevel enum value.
 */
function scoreToRisk(score: number): RiskLevel {
  if (score <= 0.1) return RiskLevel.NONE;
  if (score <= 0.3) return RiskLevel.LOW;
  if (score <= 0.5) return RiskLevel.MEDIUM;
  if (score <= 0.75) return RiskLevel.HIGH;
  return RiskLevel.CRITICAL;
}
