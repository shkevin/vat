/**
 * Node visualization components — each source/tracker type has its own component.
 * When a source or tracker is added, the graph uses the matching component to render it.
 */

import type { ComponentType } from "react";
import { AikidoNode, AIKIDO_NODE } from "./AikidoNode";
import { LinearNode, LINEAR_NODE } from "./LinearNode";

interface NodeVisualizationProps {
  x: number;
  y: number;
  width?: number;
  height?: number;
  selected?: boolean;
  onClick?: () => void;
}

/** Registry: adapter key → node component. Graph looks up by source.adapter */
export const SOURCE_NODE_REGISTRY: Record<
  string,
  {
    color: string;
    label: string;
    Component: ComponentType<NodeVisualizationProps>;
  }
> = {
  aikido: {
    color: AIKIDO_NODE.color,
    label: AIKIDO_NODE.label,
    Component: AikidoNode,
  },
};

/** Registry: tracker type → node component. Graph looks up by tracker.type */
export const TRACKER_NODE_REGISTRY: Record<
  string,
  {
    color: string;
    label: string;
    Component: ComponentType<NodeVisualizationProps & { isAdd?: boolean }>;
  }
> = {
  linear: {
    color: LINEAR_NODE.color,
    label: LINEAR_NODE.label,
    Component: LinearNode,
  },
};

/** Source types available in Add Source picker */
export const AVAILABLE_SOURCE_TYPES = ["aikido", "manual"] as const;

export { AikidoNode, AIKIDO_NODE } from "./AikidoNode";
export { AddSourceNode } from "./AddSourceNode";
export { LinearNode, LINEAR_NODE } from "./LinearNode";
