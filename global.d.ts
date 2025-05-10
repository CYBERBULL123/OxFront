/// <reference types="jest" />
/// <reference types="leaflet" />

// Add any missing module declarations here
declare module 'leaflet' {
  interface MarkerOptions {
    icon?: Icon;
  }
  
  // Ensure LatLngExpression and Icon are properly declared
  export type LatLngExpression = L.LatLngExpression;
  export type Icon = L.Icon;
}

declare module 'react-leaflet' {
  import { LatLngExpression } from 'leaflet';
  import { ReactNode } from 'react';
  
  // MapContainer props
  export interface MapContainerProps {
    center: LatLngExpression;
    zoom: number;
    style?: React.CSSProperties;
    className?: string;
    children?: ReactNode;
  }
  
  // Components
  export const MapContainer: React.FC<MapContainerProps>;
  
  export interface TileLayerProps {
    url: string;
    attribution?: string;
  }
  export const TileLayer: React.FC<TileLayerProps>;
  
  export interface MarkerProps {
    position: LatLngExpression;
    icon?: Icon;
    children?: ReactNode;
  }
  export const Marker: React.FC<MarkerProps>;
  
  export interface PopupProps {
    children?: ReactNode;
  }
  export const Popup: React.FC<PopupProps>;
  
  export interface TooltipProps {
    children?: ReactNode;
  }
  export const Tooltip: React.FC<TooltipProps>;
  export const Tooltip: React.FC<TooltipProps>;
}
