defmodule ScoutApm.Internal.Layer do
  defstruct [:type, :name, :started_at, :stopped_at, :children]

  ##################
  #  Construction  #
  ##################

  def new(%{type: type}) do
    started_at = System.monotonic_time(:microseconds)
    %__MODULE__{type: type, name: nil, started_at: started_at, children: []}
  end
  def new(%{type: type, name: name}) do
    started_at = System.monotonic_time(:microseconds)
    %__MODULE__{type: type, name: name, started_at: started_at, children: []}
  end
  def new(%{type: type, started_at: started_at}) do
    %__MODULE__{type: type, name: nil, started_at: started_at, children: []}
  end
  def new(%{type: type, name: name, started_at: started_at}) do
    %__MODULE__{type: type, name: name, started_at: started_at, children: []}
  end

  #######################
  #  Updater Functions  #
  #######################

  # Don't update a name to become nil
  def update_name(layer, nil), do: layer
  def update_name(layer, name), do: %{layer | name: name}

  def update_stopped_at(layer), do: update_stopped_at(layer, System.monotonic_time(:microseconds))
  def update_stopped_at(layer, stopped_at) do
    %{layer | stopped_at: stopped_at}
  end

  def update_children(layer, children) do
    %{layer | children: children}
  end

  #############
  #  Queries  #
  #############

  def complete?(layer) do
    layer.type != nil &&
    layer.name != nil &&
    layer.started_at != nil &&
    layer.stopped_at != nil
  end

  # TODO: Crashes when not stopped
  def total_time(layer) do
    layer.stopped_at - layer.started_at
  end

  def total_child_time(layer) do
    Enum.reduce(layer.children, 0,
      fn(child, acc) ->
        acc + total_time(child)
      end)
  end

  def total_exclusive_time(layer) do
    total_time(layer) - total_child_time(layer)
  end
end
