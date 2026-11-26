/**
 * The VPSAgent mark: a pixel "V" traced cell-for-cell from the brand sheet.
 *
 * Large mark (25×26 grid):
 *   "#"    solid cell: the stepped left arm and the base where the arms meet
 *   "1"-"9" a mesh square on the right arm; the digit is its brightness (9 = white)
 *   "."    empty
 *
 * Small mark (13×13 grid), used below 24px: the solid left arm with the right arm
 * reduced to a lattice of single pixels, as drawn on the brand sheet.
 */

const LARGE = [
  "#######..................",
  "########..........12.2121",
  ".#######.........43431...",
  ".#######.........4344434.",
  "..#######........4343334.",
  "..#######.......3434333..",
  "..#######.......3434333..",
  "...#######......3434333..",
  "...#######.....4333333...",
  "....######.....7676433...",
  "....#######....879787....",
  ".....######...6767666....",
  ".....######...7879787....",
  ".....#######..676766.....",
  "......######.8787978.....",
  "......######.767676......",
  ".......######878787......",
  ".......######76767.......",
  ".......######97879.......",
  "........#####76767.......",
  "........#######97........",
  ".........########........",
  ".........#######.........",
  ".........#######.........",
  "..........######.........",
  "..........#####..........",
];

const SMALL = [
  "####........#",
  ".###.....#.#.",
  ".###......#..",
  ".####....#...",
  "..###...#.#..",
  "..###..#.#...",
  "...###..#....",
  "...###.###...",
  "...####.#....",
  "....#####....",
  "....###.#....",
  ".....###.....",
  ".....###.....",
];

/** Mesh squares leave a gap so the grid reads; the brightest ones nearly fuse. */
const MESH_SIZE = 0.74;
const MESH_SIZE_BRIGHT = 0.86;

export interface MarkRect {
  x: number;
  y: number;
  w: number;
  h: number;
  opacity: number;
}

export interface MarkShape {
  width: number;
  height: number;
  rects: MarkRect[];
}

function build(rows: string[]): MarkShape {
  const rects: MarkRect[] = [];
  rows.forEach((row, y) => {
    let x = 0;
    while (x < row.length) {
      const ch = row[x]!;
      if (ch === "#") {
        // merge runs of solid cells so there are no hairline seams
        let end = x;
        while (row[end + 1] === "#") end++;
        rects.push({ x, y, w: end - x + 1, h: 1, opacity: 1 });
        x = end + 1;
        continue;
      }
      if (ch >= "1" && ch <= "9") {
        const level = Number(ch);
        const size = level >= 9 ? MESH_SIZE_BRIGHT : MESH_SIZE;
        const inset = (1 - size) / 2;
        rects.push({ x: x + inset, y: y + inset, w: size, h: size, opacity: level / 9 });
      }
      x++;
    }
  });
  const width = Math.max(...rows.map((r) => r.length));
  return { width, height: rows.length, rects };
}

export const LARGE_MARK = build(LARGE);
export const SMALL_MARK = build(SMALL);

export function getMark(small: boolean): MarkShape {
  return small ? SMALL_MARK : LARGE_MARK;
}

const n = (v: number) => +v.toFixed(3);

/** Standalone SVG markup (used for the favicon). */
export function markSvg(options: { fg: string; bg?: string; small?: boolean; pad?: number }): string {
  const mark = getMark(Boolean(options.small));
  const pad = options.pad ?? 0;
  const side = Math.max(mark.width, mark.height) + pad * 2;
  const ox = (side - mark.width) / 2;
  const oy = (side - mark.height) / 2;
  const rects = mark.rects
    .map(
      (r) =>
        `<rect x="${n(r.x + ox)}" y="${n(r.y + oy)}" width="${n(r.w)}" height="${n(r.h)}"${
          r.opacity < 1 ? ` fill-opacity="${n(r.opacity)}"` : ""
        }/>`,
    )
    .join("");
  const bg = options.bg
    ? `<rect width="${side}" height="${side}" rx="${n(side * 0.16)}" fill="${options.bg}"/>`
    : "";
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${side} ${side}" shape-rendering="crispEdges">${bg}<g fill="${options.fg}">${rects}</g></svg>`;
}
