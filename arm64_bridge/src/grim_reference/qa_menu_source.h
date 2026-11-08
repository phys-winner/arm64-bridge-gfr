#pragma once

// Lua 3.1, ASCII source. The selected CP1251 label is supplied via lua_pushstring.
static const char qa_menu_install_source[] = R"LUA(
GF_Port_Options_menu = special_menu
GF_Port_Options_raw_setup = rawgettable(special_menu, "setup")
GF_Port_Options_raw_handler = rawgettable(special_menu, "handler")
GF_Port_Options_setup = special_menu.setup
GF_Port_Options_handler = special_menu.handler
GF_Port_Options_captured = TRUE

-- No onChanged closure is attached to a gauge. Stock build/set_value dispatch
-- synchronously through these two restored system_prefs methods instead.
GF_Port_FPS_prefs = system_prefs
GF_Port_FPS_raw_read = rawgettable(system_prefs, "read")
GF_Port_FPS_raw_write = rawgettable(system_prefs, "write")
GF_Port_FPS_read = system_prefs.read
GF_Port_FPS_write = system_prefs.write
GF_Port_FPS_captured = TRUE
GF_Port_Language_gauges = gauge_object
GF_Port_Language_raw_build = rawgettable(gauge_object, "build")
GF_Port_Language_build = gauge_object.build
GF_Port_Language_captured = TRUE
GF_Port_Language_gauge = nil

function GF_Port_Language_build_wrapper(self)
    if self.regname == "Language" then
        if GF_Port_Language_available == 1 then
            self.max_value = 6
            self.value_text[6] = GF_Port_Language_russian_label
        end
        self.value_text[0] = GF_Port_Language_english_label
        GF_Port_Language_gauge = self
    end
    return GF_Port_Language_build(self)
end

gauge_object.build = GF_Port_Language_build_wrapper
GF_Port_FPS_mode = ReadRegistryValue("PortFPSLimitMode")
if GF_Port_FPS_mode ~= 0 and GF_Port_FPS_mode ~= 1 and GF_Port_FPS_mode ~= 2 and GF_Port_FPS_mode ~= 3 then
    GF_Port_FPS_mode = 2
end
GF_Port_FPS_additional = 0
GF_Port_FPS_failed = 0
GF_Port_FPS_commit = 0
GF_Port_FPS_gauge = nil
GF_Port_Options_requested = tostring(GF_Port_FPS_mode)

function GF_Port_FPS_read_wrapper(self, name)
    if name == "Language" then return GF_Port_Language_selection end
    if name == "PortFPSLimitMode" then return GF_Port_FPS_mode end
    return GF_Port_FPS_read(self, name)
end

function GF_Port_FPS_write_wrapper(self, name, value)
    if name == "Language" then
        if value < 0 or value > 6 or value ~= floor(value) or
            (value == 6 and GF_Port_Language_available ~= 1) then return end
        if value ~= GF_Port_Language_selection then
            if value < 6 and GF_Port_Language_active_russian ~= 1 then
                GF_Port_FPS_write(self, name, value)
            end
            GF_Port_Language_selection = value
            GF_Port_Language_requested = tostring(value)
        end
        return
    end
    if name ~= "PortFPSLimitMode" then return GF_Port_FPS_write(self, name, value) end
    if value ~= 0 and value ~= 1 and value ~= 2 and value ~= 3 then return end
    WriteRegistryValue("PortFPSLimitMode", value)
    if ReadRegistryValue("PortFPSLimitMode") == value then
        GF_Port_FPS_mode = value
        GF_Port_FPS_commit = 1
    else
        -- A full native registry is not successful persistence. Keep the last
        -- accepted mode and restore the stock gauge's just-assigned value.
        if type(GF_Port_FPS_gauge) == "table" then GF_Port_FPS_gauge.value = GF_Port_FPS_mode end
        GF_Port_FPS_failed = 1
    end
    GF_Port_Options_requested = tostring(GF_Port_FPS_mode + 4 * GF_Port_FPS_additional + 8 * GF_Port_FPS_failed + 16 * GF_Port_FPS_commit)
end

system_prefs.read = GF_Port_FPS_read_wrapper
system_prefs.write = GF_Port_FPS_write_wrapper

function GF_Port_Options_setup_wrapper(self, setup_arg)
    local found = nil
    local reference = nil
    GF_Port_FPS_gauge = nil
    local key, gauge = next(self.gauges, nil)
    while key do
        if type(gauge) == "table" then
            if gauge.regname == "RenderingMode" then reference = gauge end
            if gauge.regname == "PortFPSLimitMode" then
                GF_Port_FPS_gauge = gauge
                gauge.value = GF_Port_FPS_mode
            end
        end
        key, gauge = next(self.gauges, key)
    end
    if not GF_Port_FPS_gauge then
        -- Reuse the authored RenderingMode x/x_text, font and last-line y.
        -- add_line returns a line object, not the two placement coordinates.
        if type(reference) ~= "table" then error("FPS gauge layout unavailable") end
        self:add_line(GF_Port_FPS_label, nil, nil, nil, {literal=TRUE})
        local g = gauge_object:create("PortFPSLimitMode", TRUE, 0, 3)
        g.value_text[0] = "30"
        g.value_text[1] = "45"
        g.value_text[2] = "60"
        g.value_text[3] = GF_Port_FPS_dynamic_label
        GF_Port_FPS_gauge = g
        self:attach_gauge(g, reference.x, reference.x_text, "gf_port_fpslimit")
    end
    local key, entry = next(self.navigate, nil)
    while key do
        if type(entry) == "table" and entry.id == "gf_port_additional" then
            found = TRUE
        end
        key, entry = next(self.navigate, key)
    end
    if not found then
        self:add_line(GF_Port_Options_label, "gf_port_additional", nil, nil, {literal=TRUE})
    end
    return GF_Port_Options_setup(self, setup_arg)
end

function GF_Port_Options_handler_wrapper(self, event)
    if event == "gf_port_additional" then
        GF_Port_Options_handler(self, "return_button")
        GF_Port_FPS_additional = 1
        GF_Port_Options_requested = tostring(GF_Port_FPS_mode + 4 * GF_Port_FPS_additional + 8 * GF_Port_FPS_failed + 16 * GF_Port_FPS_commit)
    else
        return GF_Port_Options_handler(self, event)
    end
end

special_menu.setup = GF_Port_Options_setup_wrapper
special_menu.handler = GF_Port_Options_handler_wrapper
)LUA";

// Mandatory PRE Save/New/Load restoration removes all injected prototypes/globals.
static const char qa_menu_remove_source[] = R"LUA(
if GF_Port_Options_captured and type(GF_Port_Options_menu) == "table" then
    rawsettable(GF_Port_Options_menu, "setup", GF_Port_Options_raw_setup)
    rawsettable(GF_Port_Options_menu, "handler", GF_Port_Options_raw_handler)
end
if GF_Port_FPS_captured and type(GF_Port_FPS_prefs) == "table" then
    rawsettable(GF_Port_FPS_prefs, "read", GF_Port_FPS_raw_read)
    rawsettable(GF_Port_FPS_prefs, "write", GF_Port_FPS_raw_write)
end
GF_Port_FPS_prefs = nil
if GF_Port_Language_captured and type(GF_Port_Language_gauges) == "table" then
    rawsettable(GF_Port_Language_gauges, "build", GF_Port_Language_raw_build)
end
GF_Port_Language_gauges = nil
GF_Port_Language_raw_build = nil
GF_Port_Language_build = nil
GF_Port_Language_build_wrapper = nil
GF_Port_Language_captured = nil
GF_Port_Language_gauge = nil
GF_Port_Language_available = nil
GF_Port_Language_active_russian = nil
GF_Port_Language_selection = nil
GF_Port_Language_requested = nil
GF_Port_Language_russian_label = nil
GF_Port_Language_english_label = nil
GF_Port_FPS_raw_read = nil
GF_Port_FPS_raw_write = nil
GF_Port_FPS_read = nil
GF_Port_FPS_write = nil
GF_Port_FPS_read_wrapper = nil
GF_Port_FPS_write_wrapper = nil
GF_Port_FPS_captured = nil
GF_Port_FPS_mode = nil
GF_Port_FPS_additional = nil
GF_Port_FPS_failed = nil
GF_Port_FPS_commit = nil
GF_Port_FPS_gauge = nil
GF_Port_FPS_label = nil
GF_Port_FPS_dynamic_label = nil
GF_Port_Options_menu = nil
GF_Port_Options_raw_setup = nil
GF_Port_Options_raw_handler = nil
GF_Port_Options_setup = nil
GF_Port_Options_handler = nil
GF_Port_Options_setup_wrapper = nil
GF_Port_Options_handler_wrapper = nil
GF_Port_Options_label = nil
GF_Port_Options_requested = nil
GF_Port_Options_captured = nil
)LUA";
