#include "grim_gl_imports.h"
#include "thunk_manager.h"
#include "thunk_types.h"

#include <EGL/egl.h>
#include <GLES/gl.h>
#include <GLES/glext.h>
#include <GLES3/gl31.h>
#include <cstddef>
#include <cstdint>

// Existing context-aware binding mirror, also refreshed by the EGL/VAO thunks.
bool HasGlES3();
GLuint GetBoundGlBuffer(GLenum target);
void TrackGlBufferBinding(GLenum target, GLuint buffer);
void TrackGlFramebufferBinding(unsigned target, unsigned framebuffer);

namespace {

template <typename T>
T* GuestValues(DynarmicHost& host, uint32_t address, size_t count,
               const char* operation) {
    if (count == 0) return nullptr;
    const size_t arena_size = host.GetGuestMemorySize();
    if (count > arena_size / sizeof(T) || address % alignof(T) != 0 ||
        !GuestRangeValid(arena_size, address, count * sizeof(T))) {
        host.Fail(operation);
        return nullptr;
    }
    return static_cast<T*>(GuestSpan(host.GetGuestMemoryBase(), arena_size,
                                    address, count * sizeof(T)));
}

template <typename Function>
Function Extension(const char* name) {
    return reinterpret_cast<Function>(eglGetProcAddress(name));
}

// Pointer setters retain the address. Validate the first element here; subsequent
// draw extents and client-array lifetime remain the caller's contract. A VBO
// pointer is an unchanged byte offset, including offset zero, never guest memory.
bool ClientArrayPointer(DynarmicHost& host, GLint size, GLenum type,
                        uint32_t address, const void** pointer) {
    if (GetBoundGlBuffer(GL_ARRAY_BUFFER) != 0) {
        *pointer = reinterpret_cast<const void*>(static_cast<uintptr_t>(address));
        return true;
    }
    if (address == 0) {
        *pointer = nullptr;
        return true;
    }
    size_t element_size = 0;
    switch (type) {
        case GL_BYTE: element_size = 1; break;
        case GL_SHORT: element_size = 2; break;
        case GL_FIXED:
        case GL_FLOAT: element_size = 4; break;
        default: break;  // Let the real API reject the unchanged enum.
    }
    const size_t bytes = element_size && size >= 2 && size <= 4
        ? element_size * static_cast<size_t>(size) : 1;
    *pointer = GuestValues<uint8_t>(host, address, bytes,
                                  "Grim GL client-array guest span");
    return *pointer != nullptr;
}

size_t BooleanValueCount(GLenum pname) {
    switch (pname) {
        case GL_MODELVIEW_MATRIX:
        case GL_PROJECTION_MATRIX:
        case GL_TEXTURE_MATRIX:
            return 16;
        case GL_CURRENT_NORMAL:
        case GL_POINT_DISTANCE_ATTENUATION:
            return 3;
        case GL_CURRENT_COLOR:
        case GL_CURRENT_TEXTURE_COORDS:
        case GL_FOG_COLOR:
        case GL_LIGHT_MODEL_AMBIENT:
        case GL_BLEND_COLOR:
        case GL_COLOR_CLEAR_VALUE:
        case GL_COLOR_WRITEMASK:
        case GL_SCISSOR_BOX:
        case GL_VIEWPORT:
            return 4;
        case GL_SMOOTH_POINT_SIZE_RANGE:
        case GL_SMOOTH_LINE_WIDTH_RANGE:
        case GL_ALIASED_POINT_SIZE_RANGE:
        case GL_ALIASED_LINE_WIDTH_RANGE:
        case GL_DEPTH_RANGE:
        case GL_MAX_VIEWPORT_DIMS:
            return 2;
        case GL_COMPRESSED_TEXTURE_FORMATS:
        case GL_SHADER_BINARY_FORMATS:
        case GL_PROGRAM_BINARY_FORMATS: {
            const GLenum query = pname == GL_COMPRESSED_TEXTURE_FORMATS
                ? GL_NUM_COMPRESSED_TEXTURE_FORMATS
                : pname == GL_SHADER_BINARY_FORMATS
                    ? GL_NUM_SHADER_BINARY_FORMATS : GL_NUM_PROGRAM_BINARY_FORMATS;
            GLint count = 0;
            glGetIntegerv(query, &count);
            return count > 0 ? static_cast<size_t>(count) : 0;
        }
        default:
            return 1;  // Remaining GLES1/2/3.1 general state is scalar.
    }
}

}  // namespace

void RegisterGrimGlImports(ThunkManager& manager) {
    // Base AAPCS32/softfp: read every word in order, including stack spills;
    // host AArch64 then supplies the native floating-point calling convention.
    manager.RegisterThunk("glBindBufferRange", [](auto& jit, auto& host) {
        Arm32CallArgs args(jit, host);
        const GLenum target = args.U32();
        const GLuint index = args.U32();
        const GLuint buffer = args.U32();
        const GLintptr offset = args.I32();
        const GLsizeiptr size = args.I32();
        glBindBufferRange(target, index, buffer, offset, size);
        // Indexed binds also change the generic binding. Query only on a name
        // change, so a rejected call cannot invent a new mirror binding.
        GLenum query = 0;
        switch (target) {
            case GL_UNIFORM_BUFFER: query = GL_UNIFORM_BUFFER_BINDING; break;
            case GL_TRANSFORM_FEEDBACK_BUFFER:
                query = GL_TRANSFORM_FEEDBACK_BUFFER_BINDING; break;
            case GL_SHADER_STORAGE_BUFFER: query = GL_SHADER_STORAGE_BUFFER_BINDING; break;
            case GL_ATOMIC_COUNTER_BUFFER: query = GL_ATOMIC_COUNTER_BUFFER_BINDING; break;
            default: break;
        }
        if (query && HasGlES3() && GetBoundGlBuffer(target) != buffer) {
            GLint actual = 0;
            glGetIntegerv(query, &actual);
            TrackGlBufferBinding(target, static_cast<GLuint>(actual));
        }
    });

    const auto bind_framebuffer =
        Extension<PFNGLBINDFRAMEBUFFEROESPROC>("glBindFramebufferOES");
    manager.RegisterThunk("glBindFramebufferOES", [bind_framebuffer](auto& jit, auto& host) {
        if (!bind_framebuffer) { host.Fail("glBindFramebufferOES unavailable"); return; }
        const GLenum target = jit.Regs()[0];
        const GLuint framebuffer = jit.Regs()[1];
        bind_framebuffer(target, framebuffer);
        TrackGlFramebufferBinding(target, framebuffer);
    });

    const auto blend_separate =
        Extension<PFNGLBLENDFUNCSEPARATEOESPROC>("glBlendFuncSeparateOES");
    manager.RegisterThunk("glBlendFuncSeparateOES", [blend_separate](auto& jit, auto& host) {
        if (!blend_separate) { host.Fail("glBlendFuncSeparateOES unavailable"); return; }
        blend_separate(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
    });

    const auto check_framebuffer =
        Extension<PFNGLCHECKFRAMEBUFFERSTATUSOESPROC>("glCheckFramebufferStatusOES");
    manager.RegisterThunk("glCheckFramebufferStatusOES", [check_framebuffer](auto& jit, auto& host) {
        if (!check_framebuffer) { host.Fail("glCheckFramebufferStatusOES unavailable"); return; }
        jit.Regs()[0] = check_framebuffer(jit.Regs()[0]);
    });

    manager.RegisterThunk("glClearBufferfv", [](auto& jit, auto& host) {
        const GLenum buffer = jit.Regs()[0];
        const GLint drawbuffer = static_cast<GLint>(jit.Regs()[1]);
        const size_t count = buffer == GL_COLOR ? 4 : 1;
        const auto* value = GuestValues<GLfloat>(host, jit.Regs()[2], count,
                                               "glClearBufferfv guest span");
        if (!value) return;
        glClearBufferfv(buffer, drawbuffer, value);
    });

    manager.RegisterThunk("glColor4f", [](auto& jit, auto& host) {
        Arm32CallArgs args(jit, host);
        const GLfloat r = args.F32(), g = args.F32(), b = args.F32(), a = args.F32();
        glColor4f(r, g, b, a);
    });

    manager.RegisterThunk("glCompressedTexImage3D", [](auto& jit, auto& host) {
        Arm32CallArgs args(jit, host);
        const GLenum target = args.U32();
        const GLint level = args.I32();
        const GLenum format = args.U32();
        const GLsizei width = args.I32(), height = args.I32(), depth = args.I32();
        const GLint border = args.I32();
        const GLsizei image_size = args.I32();
        const uint32_t address = args.Ptr();
        const void* data = nullptr;
        if (GetBoundGlBuffer(GL_PIXEL_UNPACK_BUFFER) != 0) {
            data = reinterpret_cast<const void*>(static_cast<uintptr_t>(address));
        } else if (address && image_size > 0) {
            data = GuestValues<uint8_t>(host, address, static_cast<size_t>(image_size),
                                       "glCompressedTexImage3D guest span");
            if (!data) return;
        }
        glCompressedTexImage3D(target, level, format, width, height, depth,
                               border, image_size, data);
    });

    const auto delete_framebuffers =
        Extension<PFNGLDELETEFRAMEBUFFERSOESPROC>("glDeleteFramebuffersOES");
    manager.RegisterThunk("glDeleteFramebuffersOES", [delete_framebuffers](auto& jit, auto& host) {
        if (!delete_framebuffers) { host.Fail("glDeleteFramebuffersOES unavailable"); return; }
        const GLsizei count = static_cast<GLsizei>(jit.Regs()[0]);
        const auto* values = GuestValues<GLuint>(host, jit.Regs()[1],
            count > 0 ? static_cast<size_t>(count) : 0, "glDeleteFramebuffersOES guest span");
        if (count > 0 && !values) return;
        delete_framebuffers(count, values);
    });

    manager.RegisterThunk("glDisableClientState", [](auto& jit, auto&) {
        glDisableClientState(jit.Regs()[0]);
    });

    const auto draw_tex = Extension<PFNGLDRAWTEXFOESPROC>("glDrawTexfOES");
    manager.RegisterThunk("glDrawTexfOES", [draw_tex](auto& jit, auto& host) {
        if (!draw_tex) { host.Fail("glDrawTexfOES unavailable"); return; }
        Arm32CallArgs args(jit, host);
        const GLfloat x = args.F32(), y = args.F32(), z = args.F32();
        const GLfloat width = args.F32(), height = args.F32();
        draw_tex(x, y, z, width, height);
    });

    manager.RegisterThunk("glEnableClientState", [](auto& jit, auto&) {
        glEnableClientState(jit.Regs()[0]);
    });

    const auto framebuffer_texture =
        Extension<PFNGLFRAMEBUFFERTEXTURE2DOESPROC>("glFramebufferTexture2DOES");
    manager.RegisterThunk("glFramebufferTexture2DOES", [framebuffer_texture](auto& jit, auto& host) {
        if (!framebuffer_texture) { host.Fail("glFramebufferTexture2DOES unavailable"); return; }
        Arm32CallArgs args(jit, host);
        const GLenum target = args.U32(), attachment = args.U32(), textarget = args.U32();
        const GLuint texture = args.U32();
        const GLint level = args.I32();
        framebuffer_texture(target, attachment, textarget, texture, level);
    });

    const auto gen_framebuffers =
        Extension<PFNGLGENFRAMEBUFFERSOESPROC>("glGenFramebuffersOES");
    manager.RegisterThunk("glGenFramebuffersOES", [gen_framebuffers](auto& jit, auto& host) {
        if (!gen_framebuffers) { host.Fail("glGenFramebuffersOES unavailable"); return; }
        const GLsizei count = static_cast<GLsizei>(jit.Regs()[0]);
        auto* values = GuestValues<GLuint>(host, jit.Regs()[1],
            count > 0 ? static_cast<size_t>(count) : 0, "glGenFramebuffersOES guest span");
        if (count > 0 && !values) return;
        gen_framebuffers(count, values);
    });

    manager.RegisterThunk("glGetBooleanv", [](auto& jit, auto& host) {
        const GLenum pname = jit.Regs()[0];
        const size_t count = BooleanValueCount(pname);
        auto* values = GuestValues<GLboolean>(host, jit.Regs()[1], count,
                                             "glGetBooleanv guest span");
        if (count && !values) return;
        glGetBooleanv(pname, values);
    });

    manager.RegisterThunk("glLoadIdentity", [](auto&, auto&) { glLoadIdentity(); });
    manager.RegisterThunk("glMatrixMode", [](auto& jit, auto&) { glMatrixMode(jit.Regs()[0]); });
    manager.RegisterThunk("glOrthof", [](auto& jit, auto& host) {
        Arm32CallArgs args(jit, host);
        const GLfloat left = args.F32(), right = args.F32(), bottom = args.F32();
        const GLfloat top = args.F32(), near_value = args.F32(), far_value = args.F32();
        glOrthof(left, right, bottom, top, near_value, far_value);
    });
    manager.RegisterThunk("glPopMatrix", [](auto&, auto&) { glPopMatrix(); });
    manager.RegisterThunk("glPushMatrix", [](auto&, auto&) { glPushMatrix(); });
    manager.RegisterThunk("glRotatef", [](auto& jit, auto& host) {
        Arm32CallArgs args(jit, host);
        const GLfloat angle = args.F32(), x = args.F32(), y = args.F32(), z = args.F32();
        glRotatef(angle, x, y, z);
    });

    manager.RegisterThunk("glShaderBinary", [](auto& jit, auto& host) {
        Arm32CallArgs args(jit, host);
        const GLsizei count = args.I32();
        const uint32_t shaders_address = args.Ptr();
        const GLenum format = args.U32();
        const uint32_t binary_address = args.Ptr();
        const GLsizei length = args.I32();
        const auto* shaders = GuestValues<GLuint>(host, shaders_address,
            count > 0 ? static_cast<size_t>(count) : 0, "glShaderBinary shader span");
        const auto* binary = GuestValues<uint8_t>(host, binary_address,
            length > 0 ? static_cast<size_t>(length) : 0, "glShaderBinary binary span");
        if ((count > 0 && !shaders) || (length > 0 && !binary)) return;
        glShaderBinary(count, shaders, format, binary, length);
    });

    manager.RegisterThunk("glTexCoordPointer", [](auto& jit, auto& host) {
        const GLint size = static_cast<GLint>(jit.Regs()[0]);
        const GLenum type = jit.Regs()[1];
        const GLsizei stride = static_cast<GLsizei>(jit.Regs()[2]);
        const void* pointer = nullptr;
        if (!ClientArrayPointer(host, size, type, jit.Regs()[3], &pointer)) return;
        glTexCoordPointer(size, type, stride, pointer);
    });
    manager.RegisterThunk("glTexEnvf", [](auto& jit, auto& host) {
        Arm32CallArgs args(jit, host);
        const GLenum target = args.U32(), pname = args.U32();
        const GLfloat value = args.F32();
        glTexEnvf(target, pname, value);
    });
    manager.RegisterThunk("glTranslatef", [](auto& jit, auto& host) {
        Arm32CallArgs args(jit, host);
        const GLfloat x = args.F32(), y = args.F32(), z = args.F32();
        glTranslatef(x, y, z);
    });
    manager.RegisterThunk("glVertexPointer", [](auto& jit, auto& host) {
        const GLint size = static_cast<GLint>(jit.Regs()[0]);
        const GLenum type = jit.Regs()[1];
        const GLsizei stride = static_cast<GLsizei>(jit.Regs()[2]);
        const void* pointer = nullptr;
        if (!ClientArrayPointer(host, size, type, jit.Regs()[3], &pointer)) return;
        glVertexPointer(size, type, stride, pointer);
    });
}
