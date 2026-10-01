/**
 * Curated pool of verified benign and real DGA domains for non-repeating
 * quick-audit and demonstration workflows.
 */

export const BENIGN_DOMAINS: string[] = [
  "google.com",
  "github.com",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "wikipedia.org",
  "cloudflare.com",
  "stackoverflow.com",
  "netflix.com",
  "nytimes.com",
  "linkedin.com",
  "reddit.com",
  "spotify.com",
  "dropbox.com",
  "salesforce.com",
  "adobe.com",
  "mozilla.org",
  "python.org",
  "docker.com",
  "gitlab.com",
  "bitbucket.org",
  "slack.com",
  "zoom.us",
  "twitch.tv",
  "stripe.com",
  "paypal.com",
  "shopify.com",
  "medium.com",
  "quora.com",
  "bbc.co.uk",
  "reuters.com",
  "cnn.com",
  "bloomberg.com",
  "theguardian.com",
  "weather.com",
  "espn.com",
  "imdb.com",
  "yelp.com",
  "pinterest.com",
  "instagram.com",
  "whatsapp.com",
  "telegram.org",
  "signal.org",
  "yahoo.com",
  "bing.com",
  "duckduckgo.com",
  "archive.org",
  "apache.org",
  "ubuntu.com",
  "debian.org",
  "archlinux.org",
  "oracle.com",
  "ibm.com",
  "cisco.com",
  "intel.com",
  "nvidia.com",
  "amd.com",
  "dell.com",
  "hp.com",
  "craigslist.org",
  "ebay.com",
  "walmart.com",
  "target.com",
  "homedepot.com",
  "bestbuy.com",
  "costco.com",
  "ikea.com",
  "etsy.com",
  "booking.com",
  "airbnb.com",
  "tripadvisor.com",
  "expedia.com",
  "uber.com",
  "lyft.com",
];

export const DGA_DOMAINS: string[] = [
  // Conficker
  "ahjaccx.ir",
  "dndh.cz",
  "xsar.ro",
  // Corebot
  "ilsd5foncb14slw.ddns.net",
  "kxy8c4admn38ods.ddns.net",
  "y23lyx1d3r3hw65rs256cpk.ddns.net",
  // Cryptolocker
  "qbajjvphonqbhfy.net",
  "oteifqkcwyhapwt.com",
  "sptfjxoopxbyn.ru",
  // Dircrypt
  "rwhqwnrbxdpykemmpuq.com",
  "jchpdtknaqxelvbkm.com",
  "klfdovat.com",
  // Emotet
  "qukeodlgtqgxqrkj.eu",
  "ygqdfgjxygnkrvxc.eu",
  "flrnojnonsvmlhvh.eu",
  // Fobber
  "dmchwpzeiu.com",
  "exhwwrxofq.com",
  "aekmrdjyoy.com",
  // Gozi
  "euangeliumrationeetqu.com",
  "sacerdotumelucidande.com",
  "sacerdotumculpam.com",
  // Kraken
  "blhoecuuys.dynserv.com",
  "wceccw.com",
  "icteaqofpid.net",
  // Matsnu
  "skirtsheltermousestaydraft.com",
  "angerappreciateframechip.com",
  "racetargetbuymessappreciate.com",
  // Murofet
  "jumwirlzhulqere21msfwisize21f22c49eu.org",
  "esf32bxczntivb28bxe31g63dzaqp12dznydt.org",
  "n60l58pufslye21k27mqjwfug13dujxf32o41p32.com",
  // Necurs
  "dnwveotrhwlj.us",
  "gdlooehjslfyiushicobo.ir",
  "amuvycg.us",
  // Nymaim
  "zimbabwe-exercises.net",
  "supports-grams.ad",
  "restaurantpeeing.cn",
  // Padcrypt
  "fkcfabadafcndbma.com",
  "fnflelaldcldkcdm.co.uk",
  "nomnndkfkaekeoca.org",
  // Pushdo
  "lowinuka.ru",
  "kotumuli.ru",
  "xovokfip.ru",
  // Pykspa
  "yiyocaae.org",
  "aqzadkuiwcymao.info",
  "quqwgiaaqq.org",
  // Qadars
  "ou4y4u8mc2we.org",
  "wicaguo68ywq.net",
  "msuwa4iou8ew.net",
  // Ramdo
  "aemkaoyekyeqseso.org",
  "skmyyqsyqmmgcoim.org",
  "uoyqmymqmiyugywk.org",
  // Ramnit
  "fiygeiakxmfmt.com",
  "csexegef.com",
  "tyhomhgcfh.com",
  // Ranbyus
  "hvsktotctkyvttibu.pw",
  "neubmdyvnvlmaifwh.su",
  "qhwycogtvvdtldyir.cc",
  // Rovnix
  "fvjdzedoofwc1n8ahz.cn",
  "e8n5lcntqqivo46zo8.cn",
  "xzywtz27at7dlijzk7.cn",
  // Simda
  "wyheral.su",
  "puvycag.com",
  "kevobux.net",
  // Suppobox
  "deadbuild.net",
  "sylvesterkristina.net",
  "sightover.net",
  // Symmi
  "oktemaakakk.ddns.net",
  "upusofom.ddns.net",
  "koqoitkuap.ddns.net",
  // Tinba
  "ivrlcrsdsbpe.in",
  "pkppklesridd.biz",
  "gkvruefgdydp.pw",
  // Vawtrak
  "isdomuwgehe.com",
  "lotengu.com",
  "gicosli.com",
];

export class TestDomainSampler {
  private usedDomains: Set<string> = new Set();

  /**
   * Returns `count` unique domains (balanced between benign and real DGA families)
   * that have not been sampled previously in the current session.
   * If the remaining unused pool cannot fulfill the request, it resets the tracking
   * set gracefully to guarantee endless runs.
   */
  public sample(count: number = 6): { domains: string[]; remainingPoolSize: number } {
    const half = Math.ceil(count / 2);
    const otherHalf = count - half;

    let availableBenign = BENIGN_DOMAINS.filter((d) => !this.usedDomains.has(d));
    let availableDga = DGA_DOMAINS.filter((d) => !this.usedDomains.has(d));

    // If either pool is exhausted, reset tracking gracefully
    if (availableBenign.length < half || availableDga.length < otherHalf) {
      this.reset();
      availableBenign = [...BENIGN_DOMAINS];
      availableDga = [...DGA_DOMAINS];
    }

    const selectedBenign = availableBenign.slice(0, half);
    const selectedDga = availableDga.slice(0, otherHalf);

    const sampled = [...selectedBenign, ...selectedDga];

    // Interleave/shuffle the selection
    for (let i = sampled.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [sampled[i], sampled[j]] = [sampled[j], sampled[i]];
    }

    for (const d of sampled) {
      this.usedDomains.add(d);
    }

    const remainingPoolSize =
      BENIGN_DOMAINS.length + DGA_DOMAINS.length - this.usedDomains.size;

    return { domains: sampled, remainingPoolSize };
  }

  public reset(): void {
    this.usedDomains.clear();
  }

  public getUsedCount(): number {
    return this.usedDomains.size;
  }

  public getTotalPoolSize(): number {
    return BENIGN_DOMAINS.length + DGA_DOMAINS.length;
  }
}
