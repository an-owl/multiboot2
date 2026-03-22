//! Module for [`ElfSectionsTag`].

use crate::{TagHeader, TagType};
use core::cmp::Ordering;
use core::fmt::{Debug, Formatter};
use core::hash::Hasher;
use core::marker::PhantomData;
use core::str::Utf8Error;
use elf::section::*;
use multiboot2_common::{MaybeDynSized, Tag};
#[cfg(feature = "builder")]
use {alloc::boxed::Box, multiboot2_common::new_boxed};

const ELF32_SHDR_SIZE: u32 = size_of::<Elf32_Shdr>() as u32;
const ELF64_SHDR_SIZE: u32 = size_of::<Elf64_Shdr>() as u32;

/// This tag contains the section header table from an ELF binary.
// The sections iterator is provided via the [`ElfSectionsTag::sections`]
// method.
#[derive(ptr_meta::Pointee, PartialEq, Eq)]
#[repr(C, align(8))]
pub struct ElfSectionsTag {
    header: TagHeader,
    number_of_sections: u32,
    entry_size: u32,
    shndx: u32,
    sections: [u8],
}

impl ElfSectionsTag {
    /// Create a new ElfSectionsTag with the given data.
    #[cfg(feature = "builder")]
    #[must_use]
    pub fn new(number_of_sections: u32, entry_size: u32, shndx: u32, sections: &[u8]) -> Box<Self> {
        let header = TagHeader::new(Self::ID, 0);
        let number_of_sections = number_of_sections.to_ne_bytes();
        let entry_size = entry_size.to_ne_bytes();
        let shndx = shndx.to_ne_bytes();
        new_boxed(
            header,
            &[&number_of_sections, &entry_size, &shndx, sections],
        )
    }

    /// Get an iterator over the ELF sections.
    #[must_use]
    pub const fn sections(&self) -> ElfSectionIter<'_> {
        let string_section_offset = (self.shndx * self.entry_size) as isize;
        let string_section_ptr = unsafe {
            ShPointer::from_pointer(self.sections.as_ptr().offset(string_section_offset))
        };
        ElfSectionIter {
            current_section: ShPointer::from_pointer(self.sections.as_ptr()),
            remaining_sections: self.number_of_sections,
            entry_size: self.entry_size,
            string_section: string_section_ptr,
            _phantom_data: PhantomData,
        }
    }

    /// Returns the amount of sections.
    #[must_use]
    pub const fn number_of_sections(&self) -> u32 {
        self.number_of_sections
    }

    /// Returns the size of each entry.
    #[must_use]
    pub const fn entry_size(&self) -> u32 {
        self.entry_size
    }

    /// Returns the index of the section header string table.
    #[must_use]
    pub const fn shndx(&self) -> u32 {
        self.shndx
    }
}

impl MaybeDynSized for ElfSectionsTag {
    type Header = TagHeader;

    const BASE_SIZE: usize = size_of::<TagHeader>() + 3 * size_of::<u32>();

    fn dst_len(header: &TagHeader) -> usize {
        assert!(header.size as usize >= Self::BASE_SIZE);
        header.size as usize - Self::BASE_SIZE
    }
}

impl Tag for ElfSectionsTag {
    type IDType = TagType;

    const ID: TagType = TagType::ElfSections;
}

impl Debug for ElfSectionsTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ElfSectionsTag")
            .field("typ", &self.header.typ)
            .field("size", &self.header.size)
            .field("number_of_sections", &self.number_of_sections)
            .field("entry_size", &self.entry_size)
            .field("shndx", &self.shndx)
            .field("sections", &self.sections())
            .finish()
    }
}

/// An iterator over [`ElfSection`]s.
#[derive(Clone)]
pub struct ElfSectionIter<'a> {
    current_section: ShPointer,
    remaining_sections: u32,
    entry_size: u32,
    string_section: ShPointer,
    _phantom_data: PhantomData<&'a ()>,
}

impl<'a> Iterator for ElfSectionIter<'a> {
    type Item = ElfSection<'a>;

    fn next(&mut self) -> Option<ElfSection<'a>> {
        while self.remaining_sections != 0 {
            let section = ElfSection {
                // SAFETY: We perform a check to ensure that we are pointing to valid entries above.
                inner: SectionHeaderWrapper(unsafe { self.current_section.get(self.entry_size) }),
                string_section: self.string_section,
                entry_size: self.entry_size,
                _phantom: PhantomData,
            };

            self.current_section = unsafe { self.current_section.offset(self.entry_size, 1) };
            self.remaining_sections -= 1;

            if section.section_type() != ElfSectionType::Unused {
                return Some(section);
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (
            self.remaining_sections as usize,
            Some(self.remaining_sections as usize),
        )
    }
}

impl ExactSizeIterator for ElfSectionIter<'_> {
    fn len(&self) -> usize {
        self.remaining_sections as usize
    }
}

impl Debug for ElfSectionIter<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        /// Limit how many Elf-Sections should be debug-formatted.
        /// Can be thousands of sections for a Rust binary => this is useless output.
        /// If the user really wants this, they should debug-format the field directly.
        const ELF_SECTIONS_LIMIT: usize = 7;

        let mut debug = f.debug_list();

        self.clone().take(ELF_SECTIONS_LIMIT).for_each(|ref e| {
            debug.entry(e);
        });

        if self.clone().len() > ELF_SECTIONS_LIMIT {
            debug.entry(&"...");
        }

        debug.finish()
    }
}

/// A single generic ELF Section.
// TODO Shouldn't this be called ElfSectionPtrs, ElfSectionWrapper or so?
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ElfSection<'a> {
    inner: SectionHeaderWrapper,
    string_section: ShPointer,
    entry_size: u32,
    _phantom: PhantomData<&'a ()>,
}

impl Debug for ElfSection<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let inner = self.get();
        f.debug_struct("ElfSection")
            .field("inner", &inner)
            .field("string_section_ptr", &self.string_section)
            .finish()
    }
}

impl ElfSection<'_> {
    /// Get the section type as an `ElfSectionType` enum variant.
    #[must_use]
    pub fn section_type(&self) -> ElfSectionType {
        match self.get().typ() {
            elf::abi::SHT_NULL => ElfSectionType::Unused,
            elf::abi::SHT_PROGBITS => ElfSectionType::ProgramSection,
            elf::abi::SHT_SYMTAB => ElfSectionType::LinkerSymbolTable,
            elf::abi::SHT_STRTAB => ElfSectionType::StringTable,
            elf::abi::SHT_RELA => ElfSectionType::RelaRelocation,
            elf::abi::SHT_HASH => ElfSectionType::SymbolHashTable,
            elf::abi::SHT_DYNAMIC => ElfSectionType::DynamicLinkingTable,
            elf::abi::SHT_NOTE => ElfSectionType::Note,
            elf::abi::SHT_NOBITS => ElfSectionType::Uninitialized,
            elf::abi::SHT_REL => ElfSectionType::RelRelocation,
            elf::abi::SHT_SHLIB => ElfSectionType::Reserved,
            elf::abi::SHT_DYNSYM => ElfSectionType::DynamicLoaderSymbolTable,
            elf::abi::SHT_LOOS..=elf::abi::SHT_HIOS => ElfSectionType::EnvironmentSpecific,
            elf::abi::SHT_LOPROC..=elf::abi::SHT_HIPROC => ElfSectionType::ProcessorSpecific,
            elf::abi::SHT_LOUSER..=elf::abi::SHT_HIUSER => ElfSectionType::ProgramSpecific,
            e => {
                log::warn!("Unknown section type {e:x}. Treating as ElfSectionType::Unused");
                ElfSectionType::Unused
            }
        }
    }

    /// Returns the full section header in a type agnostic format.
    pub fn section_raw(&self) -> SectionHeader {
        self.inner.0
    }

    /// Get the "raw" section type as a `u32`
    #[must_use]
    pub fn section_type_raw(&self) -> u32 {
        self.get().typ()
    }

    /// Read the name of the section.
    pub fn name(&self) -> Result<&str, Utf8Error> {
        use core::ffi::CStr;

        // SAFETY: `string_table` returns valid pointer to the start of the string table.
        // self.get().name_index() is guaranteed by the multiboot2 spec to not be larger than the string table.
        let name_ptr = unsafe { self.string_table().offset(self.get().name_index() as isize) };

        // SAFETY: The ELF specification guarantees that this is null terminated.
        // The section above guarantees that this points to valid memory.
        // This memory is 'static not allocated.
        // The memory is never mutated.
        // We cant guarantee that the terminator is not greater than `isize::MAX` away however
        // I think this is a safe assumption.
        let t = unsafe { CStr::from_ptr(name_ptr.cast()) };
        t.to_str()
    }

    /// Get the physical start address of the section.
    #[must_use]
    pub fn start_address(&self) -> u64 {
        self.get().addr()
    }

    /// Get the physical end address of the section.
    ///
    /// This is the same as doing `section.start_address() + section.size()`
    #[must_use]
    pub fn end_address(&self) -> u64 {
        self.get().addr() + self.get().size()
    }

    /// Get the section's size in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.get().size()
    }

    /// Get the section's address alignment constraints.
    ///
    /// That is, the value of `start_address` must be congruent to 0,
    /// modulo the value of `addrlign`. Currently, only 0 and positive
    /// integral powers of two are allowed. Values 0 and 1 mean the section has no
    /// alignment constraints.
    #[must_use]
    pub fn addralign(&self) -> u64 {
        self.get().addralign()
    }

    /// Get the section's flags.
    #[must_use]
    pub fn flags(&self) -> ElfSectionFlags {
        ElfSectionFlags::from_bits_truncate(self.get().flags())
    }

    /// Check if the `ALLOCATED` flag is set in the section flags.
    #[must_use]
    pub fn is_allocated(&self) -> bool {
        self.flags().contains(ElfSectionFlags::ALLOCATED)
    }

    fn get(&self) -> &dyn ElfSectionInner {
        &self.inner.0
    }

    fn string_table(&self) -> *const u8 {
        // SAFETY: Correctness here is guaranteed by the multiboot2 spec.
        // The pointer to the string section is determined by `SelfSectionsTag::sections`
        // which guarantees that this pointer points to the valid string section header.
        unsafe { self.string_section.get(self.entry_size).addr() as *const u8 }
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
struct SectionHeaderWrapper(SectionHeader);

impl PartialOrd for SectionHeaderWrapper {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        macro_rules! actual_partial_comparison {
            ($field:ident) => {
                match self.0.$field.partial_cmp(&other.0.$field) {
                    Some(Ordering::Equal) => {} // fall though
                    Some(result) => return Some(result),
                    None => unreachable!(), // All fields implement Ord and so cannot return `None`
                }
            };
        }

        actual_partial_comparison!(sh_name);
        actual_partial_comparison!(sh_type);
        actual_partial_comparison!(sh_flags);
        actual_partial_comparison!(sh_addr);
        actual_partial_comparison!(sh_offset);
        actual_partial_comparison!(sh_size);
        actual_partial_comparison!(sh_link);
        actual_partial_comparison!(sh_info);
        actual_partial_comparison!(sh_addralign);
        actual_partial_comparison!(sh_entsize);
        Some(Ordering::Equal)
    }
}

impl Ord for SectionHeaderWrapper {
    fn cmp(&self, other: &Self) -> Ordering {
        // Should partial_cmp call this instead?
        self.partial_cmp(other).unwrap()
    }
}

impl core::hash::Hash for SectionHeaderWrapper {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.sh_name.hash(state);
        self.0.sh_type.hash(state);
        self.0.sh_flags.hash(state);
        self.0.sh_addr.hash(state);
        self.0.sh_offset.hash(state);
        self.0.sh_size.hash(state);
        self.0.sh_link.hash(state);
        self.0.sh_info.hash(state);
        self.0.sh_addralign.hash(state);
        self.0.sh_entsize.hash(state);
    }
}

/// Acts as a pointer to either [Elf32_Shdr] or [Elf64_Shdr] which is determined by the `sh_size` in methods
///
/// # Safety
///
/// Both variants have the same binary representation, so just accessing a variant is safe.
#[derive(Copy, Clone)]
union ShPointer {
    elf32: *const Elf32_Shdr,
    elf64: *const Elf64_Shdr,
}

impl Debug for ShPointer {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        unsafe { core::write!(f, "{:?}", self.elf64) }
    }
}

impl PartialEq for ShPointer {
    fn eq(&self, other: &Self) -> bool {
        unsafe { self.elf32 == other.elf32 }
    }
}

impl Eq for ShPointer {}

impl PartialOrd for ShPointer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        unsafe { self.elf64.partial_cmp(&other.elf64) }
    }
}

impl Ord for ShPointer {
    fn cmp(&self, other: &Self) -> Ordering {
        unsafe { self.elf32.cmp(&other.elf32) }
    }
}

impl core::hash::Hash for ShPointer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        unsafe { self.elf64.hash(state) }
    }
}

impl ShPointer {
    const fn from_pointer(ptr: *const u8) -> Self {
        Self {
            elf32: ptr as *const Elf32_Shdr, // The variant we use to construct this doesn't matter.
        }
    }

    /// ShPointer effectively acts as a raw pointer into either [Elf32_Shdr] or [Elf64_Shdr].
    ///
    /// This will perform the same operation as [pointer::offset](https://doc.rust-lang.org/std/primitive.pointer.html#method.offset)
    /// where the size of `T` is determined by `sh_size`.
    // What is the proper way to link to this?
    ///
    /// # Safety
    ///
    /// The caller must uphold the same preconditions as [pointer::offset](https://doc.rust-lang.org/std/primitive.pointer.html#method.offset).
    /// The caller must also ensure that `sh_size` is the correct value for the pointee variant.
    const unsafe fn offset(self, sh_size: u32, index: isize) -> Self {
        match sh_size {
            ELF32_SHDR_SIZE => {
                // SAFETY: Upheld by caller.
                unsafe {
                    Self {
                        elf32: self.elf32.offset(index),
                    }
                }
            }
            ELF64_SHDR_SIZE => unsafe {
                Self {
                    elf64: self.elf64.offset(index),
                }
            },
            _ => panic!("Unexpected entry size"), // Note: Can't use fmt in const context.
        }
    }

    /// Returns the pointee as a [SectionHeader] which is a bit-width-agnostic version of an elf section header
    ///
    /// # Safety
    ///
    /// See [core::ptr::read]
    unsafe fn get(&self, sh_size: u32) -> SectionHeader {
        match sh_size {
            ELF32_SHDR_SIZE => {
                // SAFETY: Must be upheld by caller.
                let sh32 = unsafe { self.elf32.read_unaligned() };
                SectionHeader {
                    sh_name: sh32.sh_name,
                    sh_type: sh32.sh_type,
                    sh_flags: sh32.sh_flags as u64,
                    sh_addr: sh32.sh_addr as u64,
                    sh_offset: sh32.sh_offset as u64,
                    sh_size: sh32.sh_size as u64,
                    sh_link: sh32.sh_link,
                    sh_info: sh32.sh_info,
                    sh_addralign: sh32.sh_addralign as u64,
                    sh_entsize: sh32.sh_entsize as u64,
                }
            }
            ELF64_SHDR_SIZE => {
                // SAFETY: See ELF32_SHDR_SIZE branch.
                // Note this uses `read_unaligned()` because MIRI throws an error otherwise.
                // Multiboot2 should *actually* guarantee that this is properly aligned
                // elf32 branch uses `read_unaligned` for parity.
                let sh64 = unsafe { self.elf64.read_unaligned() };
                SectionHeader {
                    sh_name: sh64.sh_name,
                    sh_type: sh64.sh_type,
                    sh_flags: sh64.sh_flags,
                    sh_addr: sh64.sh_addr,
                    sh_offset: sh64.sh_offset,
                    sh_size: sh64.sh_size,
                    sh_link: sh64.sh_link,
                    sh_info: sh64.sh_info,
                    sh_addralign: sh64.sh_addralign,
                    sh_entsize: sh64.sh_entsize,
                }
            }
            s => panic!("Unexpected entry size: {s}"),
        }
    }
}

// todo: Is this necessary anymore?
trait ElfSectionInner: Debug {
    fn name_index(&self) -> u32;

    fn typ(&self) -> u32;

    fn flags(&self) -> u64;

    fn addr(&self) -> u64;

    fn size(&self) -> u64;

    fn addralign(&self) -> u64;
}

macro_rules! impl_elf {
    ($name:ty) => {
        impl ElfSectionInner for $name {
            fn name_index(&self) -> u32 {
                self.sh_name
            }

            fn typ(&self) -> u32 {
                self.sh_type
            }

            fn flags(&self) -> u64 {
                self.sh_flags.into()
            }

            fn addr(&self) -> u64 {
                self.sh_addr.into()
            }

            fn size(&self) -> u64 {
                self.sh_size.into()
            }

            fn addralign(&self) -> u64 {
                self.sh_addralign.into()
            }
        }
    };
}

impl_elf!(SectionHeader);

/// An enum abstraction over raw ELF section types.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u32)]
pub enum ElfSectionType {
    /// This value marks the section header as inactive; it does not have an
    /// associated section. Other members of the section header have undefined
    /// values.
    Unused = elf::abi::SHT_NULL,

    /// The section holds information defined by the program, whose format and
    /// meaning are determined solely by the program.
    ProgramSection = elf::abi::SHT_PROGBITS,

    /// This section holds a linker symbol table.
    LinkerSymbolTable = elf::abi::SHT_SYMTAB,

    /// The section holds a string table.
    StringTable = elf::abi::SHT_STRTAB,

    /// The section holds relocation entries with explicit addends, such as type
    /// Elf32_Rela for the 32-bit class of object files. An object file may have
    /// multiple relocation sections.
    RelaRelocation = elf::abi::SHT_RELA,

    /// The section holds a symbol hash table.
    SymbolHashTable = elf::abi::SHT_HASH,

    /// The section holds dynamic linking tables.
    DynamicLinkingTable = elf::abi::SHT_DYNAMIC,

    /// This section holds information that marks the file in some way.
    Note = elf::abi::SHT_NOTE,

    /// A section of this type occupies no space in the file but otherwise resembles
    /// `ProgramSection`. Although this section contains no bytes, the
    /// sh_offset member contains the conceptual file offset.
    Uninitialized = elf::abi::SHT_NOBITS,

    /// The section holds relocation entries without explicit addends, such as type
    /// Elf32_Rel for the 32-bit class of object files. An object file may have
    /// multiple relocation sections.
    RelRelocation = elf::abi::SHT_REL,

    /// This section type is reserved but has unspecified semantics.
    Reserved = elf::abi::SHT_SHLIB,

    /// This section holds a dynamic loader symbol table.
    DynamicLoaderSymbolTable = elf::abi::SHT_DYNSYM,

    /// Values in this inclusive range (`[0x6000_0000, 0x6FFF_FFFF)`) are
    /// reserved for environment-specific semantics.
    EnvironmentSpecific = elf::abi::SHT_LOOS,

    /// Values in this inclusive range (`[0x7000_0000, 0x7FFF_FFFF)`) are
    /// reserved for processor-specific semantics.
    ProcessorSpecific = elf::abi::SHT_LOPROC,

    /// Values in this inclusive range (`[0x7000_0000, 0x7FFF_FFFF)`) are
    /// reserved for program-specific semantics.
    ProgramSpecific = elf::abi::SHT_LOUSER,
}

bitflags! {
    /// ELF Section bitflags.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
    #[repr(transparent)]
    pub struct ElfSectionFlags: u64 {
        /// The section contains data that should be writable during program execution.
        const WRITABLE = 0x1;

        /// The section occupies memory during the process execution.
        const ALLOCATED = 0x2;

        /// The section contains executable machine instructions.
        const EXECUTABLE = 0x4;
        // plus environment-specific use at 0x0F000000
        // plus processor-specific use at 0xF0000000
    }
}
