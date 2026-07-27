(function initializeRegionalDenialDetector(scope) {
  "use strict";

  const MAX_TEXT_CHARS = 65536;
  const MAX_BODY_TEXT_CHARS = 16000;
  const MAX_DIALOG_TEXT_CHARS = 8192;
  const MAX_PAIR_DISTANCE = 220;

  const exactPatterns = [
    /\b(?:this\s+)?(?:content|service|page|website|video|product)?\s*(?:is\s+)?(?:no\s+longer|not|currently\s+not)\s+available\s+(?:in|from)\s+(?:your|this)\s+(?:area|region|country|location)\b/i,
    /\b(?:content|service|access)\s+(?:is\s+)?(?:unavailable|restricted|blocked)\s+(?:in|from|based\s+on|due\s+to)\s+(?:your|this)?\s*(?:area|region|country|location)\b/i,
    /\bwe(?:'re|\s+are)\s+sorry[^.]{0,100}\bnot\s+available\s+in\s+your\s+(?:area|region|country)\b/i,
    /(?:контент|сервис|страница|сайт|видео)?\s*(?:больше\s+)?недоступ(?:ен|на|но|ны)\s+в\s+(?:вашем|вашей)\s+(?:регионе|стране|локации)/i,
    /доступ\s+(?:к\s+\S+\s+)?ограничен\s+в\s+(?:вашем|вашей)\s+(?:регионе|стране)/i,
    /(?:ce\s+)?contenu\s+n['’]est\s+(?:plus\s+)?pas\s+disponible\s+dans\s+votre\s+(?:région|pays)/i,
    /(?:dieser\s+)?inhalt\s+ist\s+in\s+(?:deiner|ihrer)\s+(?:region|land)\s+nicht\s+verfügbar/i,
    /(?:este\s+)?contenido\s+no\s+está\s+disponible\s+en\s+tu\s+(?:región|país|zona)/i,
    /(?:questo\s+)?contenuto\s+non\s+è\s+disponibile\s+nella\s+tua\s+(?:area|regione|paese)/i,
    /(?:この)?(?:コンテンツ|サービス)は(?:お住まいの)?(?:地域|国)では(?:ご利用|利用)いただけません/i
  ];

  const languagePairs = [
    {
      denial: /\b(?:unavailable|not\s+available|no\s+longer\s+available|not\s+supported|access\s+(?:denied|restricted|blocked))\b/gi,
      geography: /\b(?:your|this)\s+(?:area|region|country|location)\b|\bbased\s+on\s+your\s+location\b|\bdue\s+to\s+your\s+location\b|\bfrom\s+your\s+(?:country|region)\b/gi
    },
    {
      denial: /недоступ(?:ен|на|но|ны)|доступ\s+(?:ограничен|запрещён|запрещен)|заблокирован(?:о|а|ы)?/gi,
      geography: /в\s+(?:вашем|вашей)\s+(?:регионе|стране|локации)|из\s+(?:вашего|вашей)\s+(?:региона|страны)|по\s+(?:вашему|вашей)\s+местоположению/gi
    },
    {
      denial: /(?:pas|non|nicht|no)\s+(?:disponible|verfügbar)|accès\s+(?:refusé|restreint)|acceso\s+(?:denegado|restringido)/gi,
      geography: /(?:votre|tu|deiner|ihrer|tua)\s+(?:région|region|región|pays|país|land|area|paese)/gi
    }
  ];

  function normalizedText(value, limit = MAX_TEXT_CHARS) {
    return String(value || "")
      .slice(0, limit)
      .replace(/\u00a0/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }

  function firstMatchIndex(pattern, text) {
    pattern.lastIndex = 0;
    const match = pattern.exec(text);
    pattern.lastIndex = 0;
    return match ? match.index : -1;
  }

  function hasNearbySemanticPair(text) {
    for (const pair of languagePairs) {
      const denialIndex = firstMatchIndex(pair.denial, text);
      if (denialIndex < 0) {
        continue;
      }
      const geographyIndex = firstMatchIndex(pair.geography, text);
      if (
        geographyIndex >= 0 &&
        Math.abs(denialIndex - geographyIndex) <= MAX_PAIR_DISTANCE
      ) {
        return true;
      }
    }
    return false;
  }

  function semanticMatch(text) {
    if (!text) {
      return null;
    }
    if (exactPatterns.some((pattern) => pattern.test(text))) {
      return { confidenceBps: 9800, evidence: "exact" };
    }
    if (hasNearbySemanticPair(text)) {
      return { confidenceBps: 9500, evidence: "paired" };
    }
    return null;
  }

  function detectRegionalDenial(snapshot) {
    if (!snapshot || typeof snapshot !== "object") {
      return null;
    }
    const title = normalizedText(snapshot.title, 2048);
    const dialogText = normalizedText(snapshot.dialogText, MAX_DIALOG_TEXT_CHARS);
    const bodyText = normalizedText(snapshot.bodyText, MAX_TEXT_CHARS);

    const titleMatch = semanticMatch(title);
    if (titleMatch) {
      return { category: "regional_access_denied", ...titleMatch };
    }
    const dialogMatch = semanticMatch(dialogText);
    if (dialogMatch) {
      return { category: "regional_access_denied", ...dialogMatch };
    }

    const bodyIsBounded =
      snapshot.bodyTextTruncated !== true &&
      bodyText.length <= MAX_BODY_TEXT_CHARS &&
      Number(snapshot.linkCount || 0) <= 40 &&
      Number(snapshot.formCount || 0) <= 4;
    if (!bodyIsBounded) {
      return null;
    }
    const bodyMatch = semanticMatch(bodyText);
    return bodyMatch
      ? { category: "regional_access_denied", ...bodyMatch }
      : null;
  }

  scope.SlipstreamRegionalDenialDetector = Object.freeze({
    detectRegionalDenial,
    normalizedText
  });
})(globalThis);
