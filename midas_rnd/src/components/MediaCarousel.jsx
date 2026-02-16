import React, { useState, useEffect, useRef, useMemo } from 'react';

function MediaCarousel({ media, imageIntervalMs = 1000 }) {
  const [index, setIndex] = useState(0);
  const timeoutRef = useRef(null);
  const videoRef = useRef(null);

  // Shuffle media once whenever the incoming list changes
  const shuffled = useMemo(() => {
    if (!Array.isArray(media)) return [];
    const arr = [...media];
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  }, [media]);

  // Reset index if list changes
  useEffect(() => {
    setIndex(0);
  }, [shuffled.length]);

  // Auto-advance: images every imageIntervalMs
  useEffect(() => {
    if (shuffled.length === 0) return;
    const current = shuffled[index];

    clearTimeout(timeoutRef.current);

    if (current?.type === 'image') {
      timeoutRef.current = setTimeout(() => {
        setIndex((i) => (i + 1) % shuffled.length);
      }, imageIntervalMs);
    }

    return () => clearTimeout(timeoutRef.current);
  }, [index, shuffled, imageIntervalMs]);

  // Videos: play at 2x and advance on end
  useEffect(() => {
    const current = shuffled[index];
    const el = videoRef.current;

    const cleanup = () => {
      if (el) el.onended = null;
    };
    cleanup();

    if (current?.type === 'video' && el) {
      el.playbackRate = 2.0;
      const p = el.play?.();
      if (p && typeof p.then === 'function') {
        p.catch(() => {
          // Autoplay may fail without user interaction; ignore silently.
        });
      }
      el.onended = () => setIndex((i) => (i + 1) % shuffled.length);
    }

    return cleanup;
  }, [index, shuffled]);

  const goPrev = () => setIndex((i) => (i - 1 + shuffled.length) % shuffled.length);
  const goNext = () => setIndex((i) => (i + 1) % shuffled.length);

  return (
    <div className="carousel">
      {shuffled.map((item, i) => {
        const active = i === index;
        return (
          <div key={i} className={`slide ${active ? 'active' : ''}`} aria-hidden={!active}>
            {item.type === 'video' ? (
              <video
                ref={active ? videoRef : null}
                src={item.src}
                poster={item.poster}
                autoPlay
                muted
                playsInline
                loop={false}
                className="slide-media video"
              />
            ) : (
              <img
                src={item.src}
                alt={item.alt || 'AI highlight'}
                loading="lazy"
                className="slide-media image"
              />
            )}
          </div>
        );
      })}

      {shuffled.length > 1 && (
        <div className="controls">
          <button aria-label="Previous" onClick={goPrev}>‹</button>
          <div className="dots">
            {shuffled.map((_, i) => (
              <button
                key={i}
                aria-label={`Go to item ${i + 1}`}
                className={i === index ? 'active' : ''}
                onClick={() => setIndex(i)}
              />
            ))}
          </div>
          <button aria-label="Next" onClick={goNext}>›</button>
        </div>
      )}

      <style jsx>{`
        .carousel {
          position: relative;
          width: 100%;
          height: 100%;
          overflow: hidden;
          display: flex;
          align-items: center;
          justify-content: center;
          background: #000;
        }
        .slide {
          position: absolute;
          inset: 0;
          opacity: 0;
          transition: opacity 0.5s ease;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .slide.active { opacity: 1; }
        .slide-media { width: 100%; height: 100%; object-position: center center; }
        .slide-media.video { object-fit: cover; }
        .slide-media.image { object-fit: contain; background: #000; }
        .controls {
          position: absolute; bottom: 10px; left: 0; right: 0;
          display: flex; justify-content: center; align-items: center; gap: 10px; z-index: 2;
        }
        .controls > button {
          background: rgba(255,255,255,0.75); border: none; padding: 6px 10px;
          font-size: 16px; cursor: pointer; border-radius: 6px; line-height: 1;
        }
        .dots { display: flex; gap: 6px; }
        .dots button {
          width: 12px; height: 4px; padding: 0; line-height: 1;
          border-radius: 0; border: none; background: rgba(255,255,255,0.7); cursor: pointer;
        }
        .dots button.active { background: #6e45e2; }
      `}</style>
    </div>
  );
}

export default MediaCarousel;
