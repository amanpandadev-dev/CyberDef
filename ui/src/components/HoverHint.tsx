import { useEffect, useRef, useState } from 'react';

interface HoverHintState {
    visible: boolean;
    text: string;
    x: number;
    y: number;
}

const TOOLTIP_WIDTH = 240;
const OFFSET = 14;

export default function HoverHint() {
    const [state, setState] = useState<HoverHintState>({
        visible: false,
        text: '',
        x: 0,
        y: 0,
    });
    const activeRef = useRef<HTMLElement | null>(null);

    useEffect(() => {
        const handlePointerMove = (event: MouseEvent) => {
            if (!activeRef.current) return;
            const maxX = window.innerWidth - TOOLTIP_WIDTH - 12;
            const nextX = Math.max(12, Math.min(maxX, event.clientX + OFFSET));
            const nextY = Math.max(12, event.clientY + OFFSET);
            setState((prev) => ({ ...prev, x: nextX, y: nextY }));
        };

        const handlePointerOver = (event: MouseEvent) => {
            const target = (event.target as HTMLElement | null)?.closest?.('[data-help]') as HTMLElement | null;
            if (!target) return;
            const text = target.getAttribute('data-help');
            if (!text) return;
            activeRef.current = target;
            setState((prev) => ({ ...prev, visible: true, text }));
        };

        const handlePointerOut = (event: MouseEvent) => {
            const related = event.relatedTarget as HTMLElement | null;
            if (related && activeRef.current && activeRef.current.contains(related)) return;
            if (!activeRef.current) return;
            activeRef.current = null;
            setState((prev) => ({ ...prev, visible: false }));
        };

        document.addEventListener('mousemove', handlePointerMove);
        document.addEventListener('mouseover', handlePointerOver);
        document.addEventListener('mouseout', handlePointerOut);

        return () => {
            document.removeEventListener('mousemove', handlePointerMove);
            document.removeEventListener('mouseover', handlePointerOver);
            document.removeEventListener('mouseout', handlePointerOut);
        };
    }, []);

    if (!state.visible || !state.text) return null;

    return (
        <div
            className="pointer-events-none fixed z-[120] max-w-[240px] rounded-lg border border-orange-300 bg-orange-50 px-2.5 py-2 text-xs font-semibold text-orange-900 shadow-lg"
            style={{ left: state.x, top: state.y }}
        >
            {state.text}
        </div>
    );
}
