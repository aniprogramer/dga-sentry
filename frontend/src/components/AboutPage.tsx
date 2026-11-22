import { useEffect, useRef } from "react";
import BrandMark from "./BrandMark";

const REPO_URL = "https://github.com/aniprogramer/dga-sentry";
const TITLE = "About DGA Sentry — Malicious Domain Detection";
const DESCRIPTION =
  "What DGA Sentry does, how to use it, how to read its results, and where its limits are.";

const TOC = [
  ["the-problem", "The problem"],
  ["how-to-use", "How to use it"],
  ["reading-results", "Reading the results"],
  ["how-it-works", "How it works"],
  ["limitations", "Limitations"],
] as const;

interface AboutPageProps {
  /** Section id from the URL (`#/about#how-it-works`), if any. */
  section?: string;
  onTryIt: () => void;
}

export default function AboutPage({ section, onTryIt }: AboutPageProps) {
  const headingRef = useRef<HTMLHeadingElement>(null);

  // Document title and meta description while About is shown; restored on leave.
  useEffect(() => {
    const prevTitle = document.title;
    let meta = document.querySelector<HTMLMetaElement>(
      'meta[name="description"]',
    );
    const created = !meta;
    if (!meta) {
      meta = document.createElement("meta");
      meta.name = "description";
      document.head.appendChild(meta);
    }
    const prevDescription = meta.content;
    document.title = TITLE;
    meta.content = DESCRIPTION;
    return () => {
      document.title = prevTitle;
      if (created) meta.remove();
      else meta.content = prevDescription;
    };
  }, []);

  // Scroll to the requested section, or to the top with focus on the heading.
  useEffect(() => {
    const target = section ? document.getElementById(section) : null;
    if (target) {
      const reduce = window.matchMedia?.(
        "(prefers-reduced-motion: reduce)",
      ).matches;
      target.scrollIntoView({
        behavior: reduce ? "auto" : "smooth",
        block: "start",
      });
    } else {
      window.scrollTo(0, 0);
      headingRef.current?.focus({ preventScroll: true });
    }
  }, [section]);

  return (
    <article className="soc-about" aria-labelledby="about-title">
      <header className="soc-about-hero">
        <BrandMark className="soc-about-mark" size={44} />
        <h1 id="about-title" ref={headingRef} tabIndex={-1}>
          Spot machine-made domain names
        </h1>
        <p>
          DGA Sentry checks a domain name and tells you whether it looks like
          one that malware generated automatically. Type a name, get a verdict
          and see what drove it.
        </p>
      </header>

      <nav className="soc-about-toc" aria-label="On this page">
        {TOC.map(([id, label]) => (
          <a key={id} href={`#/about#${id}`}>
            {label}
          </a>
        ))}
      </nav>

      <section id="the-problem" aria-labelledby="the-problem-h">
        <h2 id="the-problem-h">The problem</h2>
        <p>
          Some malware creates thousands of random-looking domain names every
          day and tries them one by one until it finds its controller. These are
          called DGA domains, short for domain generation algorithm. Because the
          names keep changing, defenders cannot block them all ahead of time.
          Spotting them from the name alone helps catch infections early.
        </p>
      </section>

      <section id="how-to-use" aria-labelledby="how-to-use-h">
        <h2 id="how-to-use-h">How to use it</h2>
        <ol>
          <li>
            <strong>Enter a domain.</strong> Use Single Domain for one name, or
            Batch Check to paste several (up to 100). URLs are fine: the
            hostname is pulled out for you.
          </li>
          <li>
            <strong>Read the verdict.</strong> You get Allow, Monitor or Block,
            with a malicious probability.
          </li>
          <li>
            <strong>Review the explanation.</strong> The top drivers show which
            parts of the name pushed the result up or down.
          </li>
        </ol>
        <p>
          Two more tools sit in the navigation: <em>Bulk Audit</em> checks a
          pasted DNS log or CSV file, and the live DNS option adds a lookup of
          whether the domain resolves.
        </p>
      </section>

      <section id="reading-results" aria-labelledby="reading-results-h">
        <h2 id="reading-results-h">Reading the results</h2>
        <dl>
          <dt>Verdict badge</dt>
          <dd>
            ALLOW / SAFE, MONITOR / SUSPICIOUS or BLOCK / MALICIOUS. It is the
            overall call.
          </dd>
          <dt>Malicious probability</dt>
          <dd>
            How strongly the name resembles machine-generated names. Higher
            means more alike.
          </dd>
          <dt>Malware family attribution</dt>
          <dd>
            A best guess at which malware family a non-safe name resembles.
            Treat it as a hint, not an identification.
          </dd>
          <dt>Recommended action</dt>
          <dd>
            The suggested next step for the verdict: allow, monitor or block.
          </dd>
        </dl>
      </section>

      <section id="how-it-works" aria-labelledby="how-it-works-h">
        <h2 id="how-it-works-h">How it works</h2>
        <p>
          Real names are usually made of words people chose. Generated names are
          not. DGA Sentry measures patterns in the name, such as how random the
          letters look, how long it is, how letters and digits mix, and how
          word-like it is. It compares those patterns with many known real and
          generated examples to judge which group the name resembles.
        </p>
      </section>

      <section id="limitations" aria-labelledby="limitations-h">
        <h2 id="limitations-h">Limitations and responsible use</h2>
        <ul>
          <li>
            It can miss generators that join real words together, because those
            names look ordinary.
          </li>
          <li>
            It can flag legitimate names that happen to look random, such as
            some tracking or content-delivery domains.
          </li>
          <li>
            It reads only the name. It does not look at timing, traffic or live
            reputation, so use it as one signal and not as the only reason to
            block something.
          </li>
          <li>
            It learned from 25 known malware families. New families may not be
            recognized until it is retrained.
          </li>
          <li>Results are estimates, not a guarantee.</li>
        </ul>
      </section>

      <section
        id="builder"
        aria-labelledby="builder-h"
        className="soc-about-builder"
      >
        <h2 id="builder-h">About the builder</h2>
        <p>
          Built by Aniket De. Connect on{" "}
          <a
            href="https://www.linkedin.com/in/aniket-de-2a6166293/"
            target="_blank"
            rel="noopener noreferrer"
          >
            LinkedIn<span className="soc-sr-only"> (opens in a new tab)</span>
          </a>
          , or read the source and report issues on{" "}
          <a href={REPO_URL} target="_blank" rel="noopener noreferrer">
            the DGA Sentry GitHub repository
            <span className="soc-sr-only"> (opens in a new tab)</span>
          </a>
          .
        </p>
      </section>

      <div className="soc-about-cta">
        <button
          type="button"
          className="soc-btn-primary"
          onClick={onTryIt}
          id="about-try-it"
        >
          Try it now
        </button>
      </div>
    </article>
  );
}
