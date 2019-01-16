defmodule ScoutApm.Internal.Duration do
  @type t :: %__MODULE__{value: number()}
  @type unit :: :microseconds | :microsecond | :milliseconds | :millisecond | :seconds | :second

  defstruct [
    :value
  ]

  @spec zero() :: t
  def zero(), do: %__MODULE__{value: 0}

  @spec new(number(), unit) :: t
  def new(value, unit) do
    %__MODULE__{value: normalize_value(value, unit)}
  end

  @spec as(t, unit) :: number()
  def as(%__MODULE__{value: value}, :microseconds), do: value
  def as(%__MODULE__{value: value}, :microsecond), do: value
  def as(%__MODULE__{value: value}, :milliseconds), do: value / 1_000
  def as(%__MODULE__{value: value}, :millisecond), do: value / 1_000
  def as(%__MODULE__{value: value}, :seconds), do: value / 1_000_000
  def as(%__MODULE__{value: value}, :second), do: value / 1_000_000

  @spec add(t, t) :: t
  def add(%__MODULE__{value: v1}, %__MODULE__{value: v2}) do
    %__MODULE__{value: v1 + v2}
  end

  @spec subtract(t, t) :: t
  def subtract(%__MODULE__{value: v1}, %__MODULE__{value: v2}) do
    %__MODULE__{value: v1 - v2}
  end

  @spec min(t, t) :: t
  def min(%__MODULE__{value: v1}, %__MODULE__{value: v2}) do
    cond do
      v1 < v2 -> %__MODULE__{value: v1}
      v2 < v1 -> %__MODULE__{value: v2}
      v1 == v2 -> %__MODULE__{value: v1}
    end
  end

  @spec max(t, t) :: t
  def max(%__MODULE__{value: v1}, %__MODULE__{value: v2}) do
    cond do
      v1 > v2 -> %__MODULE__{value: v1}
      v2 > v1 -> %__MODULE__{value: v2}
      v1 == v2 -> %__MODULE__{value: v1}
    end
  end

  defp normalize_value(value, :microseconds), do: value
  defp normalize_value(value, :microsecond), do: value
  defp normalize_value(value, :milliseconds), do: value * 1000
  defp normalize_value(value, :millisecond), do: value * 1000
  defp normalize_value(value, :seconds), do: value * 1_000_000
  defp normalize_value(value, :second), do: value * 1_000_000
end
